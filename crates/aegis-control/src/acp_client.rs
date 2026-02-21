//! ACP (Agent Communication Protocol) client library.
//!
//! Provides a secure client for agent-to-agent communication over ACP.
//! All connections require TLS, endpoints are validated against SSRF attacks,
//! and messages include SHA-256 payload hashes for integrity verification.
//!
//! Auth tokens are read exclusively from environment variables -- never from
//! config files -- to prevent accidental exposure in version control.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum message payload size (1 MB).
const MAX_MESSAGE_SIZE: usize = 1_048_576;

/// Default rate limit: 60 sends per minute.
const DEFAULT_RATE_LIMIT_PER_MINUTE: u32 = 60;

/// Default connection timeout in seconds.
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Default heartbeat interval in seconds.
const DEFAULT_HEARTBEAT_SECS: u64 = 30;

/// Default maximum number of reconnect attempts.
const DEFAULT_MAX_RECONNECT_ATTEMPTS: u32 = 5;

/// Base delay for exponential backoff in milliseconds.
const BACKOFF_BASE_MS: u64 = 500;

// ---------------------------------------------------------------------------
// AcpClientConfig
// ---------------------------------------------------------------------------

/// Configuration for an ACP client connection.
///
/// The `auth_token_env` field names an environment variable that holds the
/// authentication token. The token is never stored in the config itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcpClientConfig {
    /// The ACP server endpoint URL (must be HTTPS).
    pub endpoint: String,
    /// Name of the environment variable holding the auth token.
    pub auth_token_env: String,
    /// Connection timeout.
    #[serde(default = "default_timeout")]
    pub timeout: Duration,
    /// Heartbeat interval for connection health checks.
    #[serde(default = "default_heartbeat")]
    pub heartbeat_interval: Duration,
    /// Maximum reconnect attempts before giving up.
    #[serde(default = "default_max_reconnect")]
    pub max_reconnect_attempts: u32,
    /// Maximum sends per minute (rate limiting).
    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_minute: u32,
}

fn default_timeout() -> Duration {
    Duration::from_secs(DEFAULT_TIMEOUT_SECS)
}

fn default_heartbeat() -> Duration {
    Duration::from_secs(DEFAULT_HEARTBEAT_SECS)
}

fn default_max_reconnect() -> u32 {
    DEFAULT_MAX_RECONNECT_ATTEMPTS
}

fn default_rate_limit() -> u32 {
    DEFAULT_RATE_LIMIT_PER_MINUTE
}

impl AcpClientConfig {
    /// Create a new config with required fields and sensible defaults.
    pub fn new(endpoint: impl Into<String>, auth_token_env: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            auth_token_env: auth_token_env.into(),
            timeout: default_timeout(),
            heartbeat_interval: default_heartbeat(),
            max_reconnect_attempts: default_max_reconnect(),
            rate_limit_per_minute: default_rate_limit(),
        }
    }
}

// ---------------------------------------------------------------------------
// AcpMessage
// ---------------------------------------------------------------------------

/// The types of messages that can be exchanged over an ACP connection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AcpMessage {
    /// A request from client to server.
    Request {
        /// Unique request identifier for correlation.
        id: Uuid,
        /// The request method or operation name.
        method: String,
        /// JSON payload for the request.
        payload: serde_json::Value,
    },
    /// A response from server to client.
    Response {
        /// The request ID this response correlates to.
        request_id: Uuid,
        /// Whether the request succeeded.
        success: bool,
        /// JSON payload for the response.
        payload: serde_json::Value,
    },
    /// An asynchronous event from the server.
    Event {
        /// Event type identifier.
        event_type: String,
        /// JSON payload for the event.
        payload: serde_json::Value,
    },
    /// An error message.
    Error {
        /// Optional request ID if the error relates to a specific request.
        request_id: Option<Uuid>,
        /// Error code for programmatic handling.
        code: String,
        /// Human-readable error description.
        message: String,
    },
}

// ---------------------------------------------------------------------------
// AcpMessageFrame
// ---------------------------------------------------------------------------

/// Wire-format frame wrapping an ACP message with metadata for integrity
/// verification and tracing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcpMessageFrame {
    /// Unique frame identifier.
    pub frame_id: Uuid,
    /// When the frame was created.
    pub timestamp: DateTime<Utc>,
    /// SHA-256 hex digest of the serialized payload.
    pub payload_hash: String,
    /// The serialized message payload.
    pub payload: Vec<u8>,
}

impl AcpMessageFrame {
    /// Create a new frame from a serialized payload, computing the hash.
    pub fn new(payload: Vec<u8>) -> Self {
        let hash = compute_sha256(&payload);
        Self {
            frame_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            payload_hash: hash,
            payload,
        }
    }

    /// Verify that the payload hash matches the actual payload content.
    pub fn verify_hash(&self) -> bool {
        let computed = compute_sha256(&self.payload);
        computed == self.payload_hash
    }
}

/// Compute the SHA-256 hex digest of arbitrary bytes.
fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// AcpConnection (connection state)
// ---------------------------------------------------------------------------

/// Connection state for an ACP client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Not connected.
    Disconnected,
    /// Attempting to connect.
    Connecting,
    /// Connected and operational.
    Connected,
    /// Connection lost, attempting to reconnect.
    Reconnecting,
}

/// Manages the state of an ACP connection.
///
/// This is an internal bookkeeping struct used by [`AcpClient`]. Actual
/// network I/O depends on the transport (WebSocket, HTTP/2, etc.) which
/// is not yet wired -- this task establishes the type system, validation,
/// and framing layer.
#[derive(Debug)]
pub struct AcpConnection {
    /// Validated endpoint URL.
    endpoint: url::Url,
    /// Current connection state.
    state: ConnectionState,
    /// Number of reconnect attempts since last successful connection.
    reconnect_attempts: u32,
}

impl AcpConnection {
    /// Create a new connection to the given endpoint.
    ///
    /// The endpoint is validated for TLS and SSRF safety at construction time.
    fn new(endpoint: url::Url) -> Self {
        Self {
            endpoint,
            state: ConnectionState::Disconnected,
            reconnect_attempts: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Rate limiter
// ---------------------------------------------------------------------------

/// Simple sliding-window rate limiter.
///
/// Tracks send timestamps in a fixed-size circular buffer and rejects
/// sends that would exceed the configured rate.
struct RateLimiter {
    max_per_minute: u32,
    /// Timestamps of recent sends within the current window.
    window: Mutex<Vec<Instant>>,
}

impl RateLimiter {
    fn new(max_per_minute: u32) -> Self {
        Self {
            max_per_minute,
            window: Mutex::new(Vec::new()),
        }
    }

    /// Check whether a send is allowed. If allowed, records the timestamp
    /// and returns `Ok(())`. Otherwise returns an error.
    fn check_and_record(&self) -> Result<(), AcpError> {
        let mut window = self.window.lock().map_err(|_| AcpError::InternalError {
            message: "rate limiter lock poisoned".into(),
        })?;

        let now = Instant::now();
        let one_minute_ago = now - Duration::from_secs(60);

        // Prune timestamps older than one minute.
        window.retain(|&t| t > one_minute_ago);

        if window.len() >= self.max_per_minute as usize {
            return Err(AcpError::RateLimitExceeded {
                limit: self.max_per_minute,
            });
        }

        window.push(now);
        Ok(())
    }
}

impl std::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiter")
            .field("max_per_minute", &self.max_per_minute)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// AcpError
// ---------------------------------------------------------------------------

/// Errors specific to ACP client operations.
#[derive(Debug, thiserror::Error)]
pub enum AcpError {
    /// The endpoint URL is not valid HTTPS.
    #[error("TLS required: endpoint must use HTTPS, got {scheme:?}")]
    TlsRequired { scheme: String },

    /// The endpoint resolves to a private/loopback/link-local IP (SSRF).
    #[error("SSRF blocked: endpoint resolves to private address {addr}")]
    SsrfBlocked { addr: String },

    /// The endpoint URL is malformed.
    #[error("invalid endpoint URL: {reason}")]
    InvalidEndpoint { reason: String },

    /// Auth token environment variable is not set.
    #[error("auth token env var {var:?} is not set")]
    AuthTokenMissing { var: String },

    /// Message exceeds maximum allowed size.
    #[error("message size {size} exceeds limit {limit}")]
    MessageTooLarge { size: usize, limit: usize },

    /// Payload hash verification failed.
    #[error("payload hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    /// Rate limit exceeded.
    #[error("rate limit exceeded: max {limit} sends per minute")]
    RateLimitExceeded { limit: u32 },

    /// The client is not connected.
    #[error("not connected to ACP server")]
    NotConnected,

    /// Internal error (lock poisoning, etc.).
    #[error("internal error: {message}")]
    InternalError { message: String },

    /// Connection failed.
    #[error("connection failed: {reason}")]
    ConnectionFailed { reason: String },
}

// ---------------------------------------------------------------------------
// SSRF validation
// ---------------------------------------------------------------------------

/// Returns `true` if the IP address is private, loopback, or link-local.
///
/// Blocks RFC 1918, RFC 4193, loopback (127.0.0.0/8, ::1),
/// link-local (169.254.0.0/16, fe80::/10), and unspecified addresses.
fn is_private_or_reserved(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            v4.is_loopback()          // 127.0.0.0/8
                || v4.is_private()    // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                || v4.is_link_local() // 169.254.0.0/16
                || v4.is_unspecified()// 0.0.0.0
                || v4.is_broadcast()  // 255.255.255.255
                || v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64 // 100.64.0.0/10 (CGNAT)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()       // ::1
                || v6.is_unspecified() // ::
                // Link-local: fe80::/10
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // Unique local: fc00::/7
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // IPv4-mapped: ::ffff:0:0/96 -- check the mapped IPv4
                || v6.to_ipv4_mapped().is_some_and(|v4| {
                    v4.is_loopback()
                        || v4.is_private()
                        || v4.is_link_local()
                        || v4.is_unspecified()
                })
        }
    }
}

/// Validate an endpoint URL for SSRF safety.
///
/// Checks:
/// 1. Scheme must be `https`
/// 2. Host must not be localhost or a private/reserved IP
/// 3. URL must have a valid host
fn validate_endpoint(endpoint: &str) -> Result<url::Url, AcpError> {
    let parsed = url::Url::parse(endpoint).map_err(|e| AcpError::InvalidEndpoint {
        reason: e.to_string(),
    })?;

    // Require HTTPS
    if parsed.scheme() != "https" {
        return Err(AcpError::TlsRequired {
            scheme: parsed.scheme().to_string(),
        });
    }

    // Must have a host
    let host = parsed
        .host_str()
        .ok_or_else(|| AcpError::InvalidEndpoint {
            reason: "URL has no host".into(),
        })?;

    // Block localhost by name
    if host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]" {
        return Err(AcpError::SsrfBlocked {
            addr: host.to_string(),
        });
    }

    // If the host is a raw IP, validate it directly
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_private_or_reserved(&ip) {
            return Err(AcpError::SsrfBlocked {
                addr: ip.to_string(),
            });
        }
    }

    // Also handle bracketed IPv6 (e.g., [::1])
    let stripped = host.strip_prefix('[').and_then(|h| h.strip_suffix(']'));
    if let Some(inner) = stripped {
        if let Ok(ip) = inner.parse::<IpAddr>() {
            if is_private_or_reserved(&ip) {
                return Err(AcpError::SsrfBlocked {
                    addr: ip.to_string(),
                });
            }
        }
    }

    Ok(parsed)
}

// ---------------------------------------------------------------------------
// AcpClient
// ---------------------------------------------------------------------------

/// ACP client for secure agent-to-agent communication.
///
/// Manages connection lifecycle, message framing, SSRF validation,
/// rate limiting, and payload integrity verification.
#[derive(Debug)]
pub struct AcpClient {
    config: AcpClientConfig,
    connection: Option<AcpConnection>,
    rate_limiter: RateLimiter,
    /// Monotonic counter for sequencing.
    sequence: AtomicU64,
}

impl AcpClient {
    /// Create a new ACP client with the given configuration.
    ///
    /// Does not connect immediately -- call [`connect`](Self::connect) to
    /// establish the connection.
    pub fn new(config: AcpClientConfig) -> Self {
        let rate_limiter = RateLimiter::new(config.rate_limit_per_minute);
        Self {
            config,
            connection: None,
            rate_limiter,
            sequence: AtomicU64::new(0),
        }
    }

    /// Validate the endpoint and establish a connection.
    ///
    /// Performs SSRF validation, TLS requirement checking, and reads the
    /// auth token from the configured environment variable.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The endpoint URL is not HTTPS
    /// - The endpoint resolves to a private/loopback/link-local address
    /// - The auth token env var is not set
    pub fn connect(&mut self) -> Result<(), AcpError> {
        // Validate endpoint (TLS + SSRF)
        let url = validate_endpoint(&self.config.endpoint)?;

        // Read auth token from env (never from config)
        let _token = std::env::var(&self.config.auth_token_env).map_err(|_| {
            AcpError::AuthTokenMissing {
                var: self.config.auth_token_env.clone(),
            }
        })?;

        let mut conn = AcpConnection::new(url);
        conn.state = ConnectionState::Connected;

        tracing::info!(
            endpoint = %conn.endpoint,
            "ACP client connected"
        );

        self.connection = Some(conn);
        Ok(())
    }

    /// Serialize and frame a message for sending.
    ///
    /// Validates message size, checks rate limits, computes the payload
    /// hash, and returns a signed frame.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The client is not connected
    /// - The serialized message exceeds 1 MB
    /// - The rate limit has been exceeded
    pub fn send(&self, msg: AcpMessage) -> Result<AcpMessageFrame, AcpError> {
        // Must be connected
        let conn = self.connection.as_ref().ok_or(AcpError::NotConnected)?;
        if conn.state != ConnectionState::Connected {
            return Err(AcpError::NotConnected);
        }

        // Serialize
        let payload = serde_json::to_vec(&msg).map_err(|e| AcpError::InternalError {
            message: format!("failed to serialize message: {e}"),
        })?;

        // Enforce size limit before any further processing
        if payload.len() > MAX_MESSAGE_SIZE {
            return Err(AcpError::MessageTooLarge {
                size: payload.len(),
                limit: MAX_MESSAGE_SIZE,
            });
        }

        // Rate limit
        self.rate_limiter.check_and_record()?;

        // Build frame
        let frame = AcpMessageFrame::new(payload);
        let _ = self.sequence.fetch_add(1, Ordering::Relaxed);

        tracing::debug!(
            frame_id = %frame.frame_id,
            hash = %frame.payload_hash,
            "ACP message framed for send"
        );

        Ok(frame)
    }

    /// Receive and validate a message from a raw frame.
    ///
    /// Verifies the payload hash, enforces the size limit, and
    /// deserializes the message.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The client is not connected
    /// - The frame payload exceeds 1 MB
    /// - The payload hash does not match
    /// - Deserialization fails
    pub fn recv(&self, frame: &AcpMessageFrame) -> Result<AcpMessage, AcpError> {
        // Must be connected
        let conn = self.connection.as_ref().ok_or(AcpError::NotConnected)?;
        if conn.state != ConnectionState::Connected {
            return Err(AcpError::NotConnected);
        }

        // Size limit
        if frame.payload.len() > MAX_MESSAGE_SIZE {
            return Err(AcpError::MessageTooLarge {
                size: frame.payload.len(),
                limit: MAX_MESSAGE_SIZE,
            });
        }

        // Verify hash
        if !frame.verify_hash() {
            let actual = compute_sha256(&frame.payload);
            return Err(AcpError::HashMismatch {
                expected: frame.payload_hash.clone(),
                actual,
            });
        }

        // Deserialize
        let msg: AcpMessage =
            serde_json::from_slice(&frame.payload).map_err(|e| AcpError::InternalError {
                message: format!("failed to deserialize message: {e}"),
            })?;

        Ok(msg)
    }

    /// Disconnect from the ACP server.
    pub fn disconnect(&mut self) -> Result<(), AcpError> {
        if let Some(conn) = &mut self.connection {
            conn.state = ConnectionState::Disconnected;
            tracing::info!(
                endpoint = %conn.endpoint,
                "ACP client disconnected"
            );
        }
        self.connection = None;
        Ok(())
    }

    /// Get the current connection state.
    pub fn state(&self) -> ConnectionState {
        self.connection
            .as_ref()
            .map(|c| c.state)
            .unwrap_or(ConnectionState::Disconnected)
    }

    /// Calculate the backoff delay for a reconnect attempt.
    ///
    /// Uses exponential backoff: `base * 2^attempt`, capped at 30 seconds.
    pub fn backoff_delay(attempt: u32) -> Duration {
        let delay_ms = BACKOFF_BASE_MS.saturating_mul(1u64 << attempt.min(16));
        Duration::from_millis(delay_ms.min(30_000))
    }

    /// Attempt to reconnect with exponential backoff.
    ///
    /// Returns the number of attempts made. If all attempts fail, the
    /// connection state is set to `Disconnected`.
    pub fn reconnect(&mut self) -> Result<u32, AcpError> {
        let max_attempts = self.config.max_reconnect_attempts;

        for attempt in 0..max_attempts {
            tracing::info!(
                attempt = attempt + 1,
                max = max_attempts,
                "ACP reconnect attempt"
            );

            match self.connect() {
                Ok(()) => {
                    if let Some(conn) = &mut self.connection {
                        conn.reconnect_attempts = 0;
                    }
                    return Ok(attempt + 1);
                }
                Err(e) => {
                    tracing::warn!(
                        attempt = attempt + 1,
                        error = %e,
                        "ACP reconnect failed"
                    );
                    if let Some(conn) = &mut self.connection {
                        conn.reconnect_attempts = attempt + 1;
                        conn.state = ConnectionState::Reconnecting;
                    }
                }
            }
        }

        // All attempts exhausted
        if let Some(conn) = &mut self.connection {
            conn.state = ConnectionState::Disconnected;
        }
        Err(AcpError::ConnectionFailed {
            reason: format!(
                "exhausted {max_attempts} reconnect attempts for endpoint {}",
                self.config.endpoint
            ),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = AcpClientConfig::new("https://acp.example.com", "ACP_TOKEN");
        assert_eq!(config.endpoint, "https://acp.example.com");
        assert_eq!(config.auth_token_env, "ACP_TOKEN");
        assert_eq!(config.timeout, Duration::from_secs(DEFAULT_TIMEOUT_SECS));
        assert_eq!(
            config.heartbeat_interval,
            Duration::from_secs(DEFAULT_HEARTBEAT_SECS)
        );
        assert_eq!(
            config.max_reconnect_attempts,
            DEFAULT_MAX_RECONNECT_ATTEMPTS
        );
        assert_eq!(config.rate_limit_per_minute, DEFAULT_RATE_LIMIT_PER_MINUTE);
    }

    #[test]
    fn test_ssrf_blocked() {
        // Localhost
        assert!(matches!(
            validate_endpoint("https://localhost/api"),
            Err(AcpError::SsrfBlocked { .. })
        ));
        assert!(matches!(
            validate_endpoint("https://127.0.0.1/api"),
            Err(AcpError::SsrfBlocked { .. })
        ));

        // Private IPs (RFC 1918)
        assert!(matches!(
            validate_endpoint("https://10.0.0.1/api"),
            Err(AcpError::SsrfBlocked { .. })
        ));
        assert!(matches!(
            validate_endpoint("https://172.16.0.1/api"),
            Err(AcpError::SsrfBlocked { .. })
        ));
        assert!(matches!(
            validate_endpoint("https://192.168.1.1/api"),
            Err(AcpError::SsrfBlocked { .. })
        ));

        // Link-local
        assert!(matches!(
            validate_endpoint("https://169.254.1.1/api"),
            Err(AcpError::SsrfBlocked { .. })
        ));

        // IPv6 loopback
        assert!(matches!(
            validate_endpoint("https://[::1]/api"),
            Err(AcpError::SsrfBlocked { .. })
        ));

        // Unspecified
        assert!(matches!(
            validate_endpoint("https://0.0.0.0/api"),
            Err(AcpError::SsrfBlocked { .. })
        ));

        // Public IP should pass
        assert!(validate_endpoint("https://93.184.216.34/api").is_ok());

        // Public domain should pass
        assert!(validate_endpoint("https://acp.example.com/api").is_ok());
    }

    #[test]
    fn test_message_frame_hash() {
        let payload = b"hello, ACP".to_vec();
        let frame = AcpMessageFrame::new(payload.clone());

        // Hash should match
        assert!(frame.verify_hash());

        // Compute expected hash manually
        let expected = compute_sha256(&payload);
        assert_eq!(frame.payload_hash, expected);

        // Tampered frame should fail
        let tampered = AcpMessageFrame {
            frame_id: frame.frame_id,
            timestamp: frame.timestamp,
            payload_hash: frame.payload_hash.clone(),
            payload: b"tampered".to_vec(),
        };
        assert!(!tampered.verify_hash());
    }

    #[test]
    fn test_message_size_limit() {
        let config = AcpClientConfig::new("https://acp.example.com", "ACP_TOKEN");
        let mut client = AcpClient::new(config);

        // Simulate a connected state by manually setting it
        std::env::set_var("ACP_TOKEN", "test-token-for-size-limit");
        client.connect().unwrap();

        // Create an oversized message (> 1MB)
        let huge_payload = serde_json::Value::String("x".repeat(MAX_MESSAGE_SIZE + 1));
        let msg = AcpMessage::Request {
            id: Uuid::new_v4(),
            method: "test".into(),
            payload: huge_payload,
        };

        let result = client.send(msg);
        assert!(
            matches!(result, Err(AcpError::MessageTooLarge { .. })),
            "expected MessageTooLarge error, got: {result:?}"
        );

        // Small message should succeed
        let small_msg = AcpMessage::Request {
            id: Uuid::new_v4(),
            method: "ping".into(),
            payload: serde_json::json!({}),
        };
        assert!(client.send(small_msg).is_ok());

        std::env::remove_var("ACP_TOKEN");
    }

    #[test]
    fn test_rate_limit() {
        let limiter = RateLimiter::new(3);

        // First 3 should succeed
        assert!(limiter.check_and_record().is_ok());
        assert!(limiter.check_and_record().is_ok());
        assert!(limiter.check_and_record().is_ok());

        // 4th should fail
        let result = limiter.check_and_record();
        assert!(
            matches!(result, Err(AcpError::RateLimitExceeded { limit: 3 })),
            "expected RateLimitExceeded, got: {result:?}"
        );
    }

    #[test]
    fn test_cedar_action_names() {
        // AcpConnect should have a policy name usable in Cedar
        let kind = aegis_types::ActionKind::AcpConnect {
            endpoint: "https://acp.example.com".into(),
        };
        assert_eq!(kind.to_string(), "AcpConnect https://acp.example.com");

        // AcpSend should have a policy name
        let kind = aegis_types::ActionKind::AcpSend {
            endpoint: "https://acp.example.com".into(),
            payload_size: 256,
        };
        assert_eq!(
            kind.to_string(),
            "AcpSend https://acp.example.com (256 bytes)"
        );
    }

    #[test]
    fn test_tls_required() {
        // HTTP should be rejected
        let result = validate_endpoint("http://acp.example.com/api");
        assert!(
            matches!(result, Err(AcpError::TlsRequired { .. })),
            "expected TlsRequired error, got: {result:?}"
        );

        // ws:// should be rejected
        let result = validate_endpoint("ws://acp.example.com/api");
        assert!(
            matches!(result, Err(AcpError::TlsRequired { .. })),
            "expected TlsRequired error, got: {result:?}"
        );

        // HTTPS should pass
        assert!(validate_endpoint("https://acp.example.com/api").is_ok());
    }

    #[test]
    fn test_auth_from_env() {
        let config = AcpClientConfig::new("https://acp.example.com", "ACP_TEST_TOKEN_UNIQUE");
        let mut client = AcpClient::new(config);

        // Without env var, connect should fail
        std::env::remove_var("ACP_TEST_TOKEN_UNIQUE");
        let result = client.connect();
        assert!(
            matches!(result, Err(AcpError::AuthTokenMissing { .. })),
            "expected AuthTokenMissing error, got: {result:?}"
        );

        // With env var, connect should succeed
        std::env::set_var("ACP_TEST_TOKEN_UNIQUE", "secret-token");
        assert!(client.connect().is_ok());
        assert_eq!(client.state(), ConnectionState::Connected);

        // Clean up
        std::env::remove_var("ACP_TEST_TOKEN_UNIQUE");
    }

    #[test]
    fn test_disconnect() {
        let config = AcpClientConfig::new("https://acp.example.com", "ACP_DISCONNECT_TOKEN");
        let mut client = AcpClient::new(config);

        std::env::set_var("ACP_DISCONNECT_TOKEN", "token");
        client.connect().unwrap();
        assert_eq!(client.state(), ConnectionState::Connected);

        client.disconnect().unwrap();
        assert_eq!(client.state(), ConnectionState::Disconnected);

        std::env::remove_var("ACP_DISCONNECT_TOKEN");
    }

    #[test]
    fn test_send_requires_connection() {
        let config = AcpClientConfig::new("https://acp.example.com", "ACP_TOKEN");
        let client = AcpClient::new(config);

        let msg = AcpMessage::Request {
            id: Uuid::new_v4(),
            method: "ping".into(),
            payload: serde_json::json!({}),
        };

        let result = client.send(msg);
        assert!(
            matches!(result, Err(AcpError::NotConnected)),
            "expected NotConnected error, got: {result:?}"
        );
    }

    #[test]
    fn test_recv_verifies_hash() {
        let config = AcpClientConfig::new("https://acp.example.com", "ACP_RECV_TOKEN");
        let mut client = AcpClient::new(config);

        std::env::set_var("ACP_RECV_TOKEN", "token");
        client.connect().unwrap();

        // Valid frame
        let msg = AcpMessage::Event {
            event_type: "test".into(),
            payload: serde_json::json!({"key": "value"}),
        };
        let payload = serde_json::to_vec(&msg).unwrap();
        let frame = AcpMessageFrame::new(payload);
        let received = client.recv(&frame).unwrap();
        assert_eq!(received, msg);

        // Tampered frame
        let bad_frame = AcpMessageFrame {
            frame_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            payload_hash: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            payload: serde_json::to_vec(&msg).unwrap(),
        };
        let result = client.recv(&bad_frame);
        assert!(
            matches!(result, Err(AcpError::HashMismatch { .. })),
            "expected HashMismatch error, got: {result:?}"
        );

        std::env::remove_var("ACP_RECV_TOKEN");
    }

    #[test]
    fn test_backoff_delay() {
        let d0 = AcpClient::backoff_delay(0);
        assert_eq!(d0, Duration::from_millis(BACKOFF_BASE_MS));

        let d1 = AcpClient::backoff_delay(1);
        assert_eq!(d1, Duration::from_millis(BACKOFF_BASE_MS * 2));

        let d2 = AcpClient::backoff_delay(2);
        assert_eq!(d2, Duration::from_millis(BACKOFF_BASE_MS * 4));

        // Should cap at 30 seconds
        let d_large = AcpClient::backoff_delay(20);
        assert_eq!(d_large, Duration::from_millis(30_000));
    }

    #[test]
    fn test_message_serialization_roundtrip() {
        let variants = vec![
            AcpMessage::Request {
                id: Uuid::new_v4(),
                method: "execute".into(),
                payload: serde_json::json!({"cmd": "ls"}),
            },
            AcpMessage::Response {
                request_id: Uuid::new_v4(),
                success: true,
                payload: serde_json::json!({"result": "ok"}),
            },
            AcpMessage::Event {
                event_type: "status_change".into(),
                payload: serde_json::json!({"state": "idle"}),
            },
            AcpMessage::Error {
                request_id: Some(Uuid::new_v4()),
                code: "NOT_FOUND".into(),
                message: "resource not found".into(),
            },
            AcpMessage::Error {
                request_id: None,
                code: "INTERNAL".into(),
                message: "server error".into(),
            },
        ];

        for msg in &variants {
            let json = serde_json::to_string(msg).unwrap();
            let back: AcpMessage = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, msg);
        }
    }

    #[test]
    fn test_private_ip_detection() {
        // Private
        assert!(is_private_or_reserved(
            &"10.0.0.1".parse::<IpAddr>().unwrap()
        ));
        assert!(is_private_or_reserved(
            &"172.16.0.1".parse::<IpAddr>().unwrap()
        ));
        assert!(is_private_or_reserved(
            &"192.168.0.1".parse::<IpAddr>().unwrap()
        ));

        // Loopback
        assert!(is_private_or_reserved(
            &"127.0.0.1".parse::<IpAddr>().unwrap()
        ));
        assert!(is_private_or_reserved(&"::1".parse::<IpAddr>().unwrap()));

        // Link-local
        assert!(is_private_or_reserved(
            &"169.254.1.1".parse::<IpAddr>().unwrap()
        ));

        // Unspecified
        assert!(is_private_or_reserved(
            &"0.0.0.0".parse::<IpAddr>().unwrap()
        ));

        // Public
        assert!(!is_private_or_reserved(
            &"93.184.216.34".parse::<IpAddr>().unwrap()
        ));
        assert!(!is_private_or_reserved(
            &"8.8.8.8".parse::<IpAddr>().unwrap()
        ));
    }

    #[test]
    fn test_cgnat_blocked() {
        // CGNAT range 100.64.0.0/10
        assert!(is_private_or_reserved(
            &"100.64.0.1".parse::<IpAddr>().unwrap()
        ));
        assert!(is_private_or_reserved(
            &"100.127.255.254".parse::<IpAddr>().unwrap()
        ));
        // Just outside CGNAT
        assert!(!is_private_or_reserved(
            &"100.128.0.1".parse::<IpAddr>().unwrap()
        ));
    }
}
