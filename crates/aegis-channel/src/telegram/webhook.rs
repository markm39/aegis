//! Webhook receiver for Telegram Bot API updates.
//!
//! Instead of long-polling via `getUpdates`, Telegram can POST updates
//! directly to an HTTPS endpoint. This module provides a
//! [`WebhookReceiver`] that validates incoming requests and feeds parsed
//! [`InboundAction`]s into the same mpsc channel the poller uses.
//!
//! Security properties:
//! - Secret token validation uses constant-time comparison (prevents timing attacks)
//! - Requests without a valid secret token are rejected (fail closed)
//! - Source IP is logged for audit purposes

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::Router;
use subtle::ConstantTimeEq;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::channel::InboundAction;
use crate::format;

use super::api::TelegramApi;
use super::types::Update;

/// Shared state for the webhook handler.
struct WebhookState {
    /// Expected secret token for request validation.
    secret_token: String,
    /// Telegram API client for sending responses (help text, ack callbacks).
    api: Arc<TelegramApi>,
    /// Chat ID to filter incoming updates.
    chat_id: i64,
    /// Channel to forward parsed actions to the supervisor.
    action_tx: mpsc::Sender<InboundAction>,
}

/// Webhook receiver that listens for incoming Telegram updates via HTTP POST.
///
/// Use [`WebhookReceiver::start`] to bind and run the HTTP server. The server
/// validates the `X-Telegram-Bot-Api-Secret-Token` header using constant-time
/// comparison, parses the Update JSON, and forwards actions through the same
/// mpsc channel that the poller uses.
pub struct WebhookReceiver {
    /// Port to listen on.
    port: u16,
    /// Secret token for validation.
    secret_token: String,
    /// Telegram API client.
    api: Arc<TelegramApi>,
    /// Chat ID to filter updates.
    chat_id: i64,
}

impl WebhookReceiver {
    /// Create a new webhook receiver.
    ///
    /// The `secret_token` is compared against the
    /// `X-Telegram-Bot-Api-Secret-Token` header on each request using
    /// constant-time equality to prevent timing attacks.
    pub fn new(port: u16, secret_token: String, api: Arc<TelegramApi>, chat_id: i64) -> Self {
        Self {
            port,
            secret_token,
            api,
            chat_id,
        }
    }

    /// Start the webhook HTTP server.
    ///
    /// Returns the mpsc receiver for inbound actions and a join handle for
    /// the server task. The server runs until the returned handle is aborted
    /// or the process exits.
    pub async fn start(
        self,
    ) -> Result<(mpsc::Receiver<InboundAction>, tokio::task::JoinHandle<()>), std::io::Error> {
        let (action_tx, action_rx) = mpsc::channel(64);

        let state = Arc::new(WebhookState {
            secret_token: self.secret_token,
            api: self.api,
            chat_id: self.chat_id,
            action_tx,
        });

        let app = Router::new()
            .route("/webhook", post(handle_webhook))
            .with_state(state);

        let addr = SocketAddr::from(([0, 0, 0, 0], self.port));
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;

        info!("Telegram webhook server listening on {}", local_addr);

        let handle = tokio::spawn(async move {
            if let Err(e) = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            {
                warn!("webhook server error: {e}");
            }
        });

        Ok((action_rx, handle))
    }
}

/// Header name for the Telegram secret token.
const SECRET_TOKEN_HEADER: &str = "x-telegram-bot-api-secret-token";

/// Validate the secret token using constant-time comparison.
///
/// This prevents timing side-channels that could leak the token value.
fn validate_secret(expected: &str, provided: &str) -> bool {
    let expected_bytes = expected.as_bytes();
    let provided_bytes = provided.as_bytes();

    // Constant-time comparison: both length check and content check
    // are performed in constant time to prevent timing attacks.
    if expected_bytes.len() != provided_bytes.len() {
        // Even when lengths differ, perform a dummy comparison to maintain
        // constant-time behavior. Compare expected against itself to burn
        // the same amount of time.
        let _ = expected_bytes.ct_eq(expected_bytes);
        return false;
    }

    expected_bytes.ct_eq(provided_bytes).into()
}

/// Known Telegram webhook IP ranges (IPv4 CIDR blocks).
///
/// Telegram sends webhook requests from these IP ranges:
/// - 149.154.160.0/20
/// - 91.108.4.0/22
///
/// We log a warning for requests from outside these ranges rather than
/// rejecting them, since Telegram may add new ranges without notice and
/// the secret token provides the primary authentication.
const TELEGRAM_IP_RANGES: &[(&str, u32)] = &[
    // 149.154.160.0/20 -> 149.154.160.0 - 149.154.175.255
    ("149.154.160.0", 20),
    // 91.108.4.0/22 -> 91.108.4.0 - 91.108.7.255
    ("91.108.4.0", 22),
];

/// Check if an IP address falls within known Telegram webhook ranges.
fn is_telegram_ip(addr: &SocketAddr) -> bool {
    match addr {
        SocketAddr::V4(v4) => {
            let ip = u32::from(*v4.ip());
            for &(cidr_base, prefix_len) in TELEGRAM_IP_RANGES {
                if let Ok(base_addr) = cidr_base.parse::<std::net::Ipv4Addr>() {
                    let base = u32::from(base_addr);
                    let mask = if prefix_len == 0 {
                        0
                    } else {
                        !0u32 << (32 - prefix_len)
                    };
                    if (ip & mask) == (base & mask) {
                        return true;
                    }
                }
            }
            false
        }
        // Telegram webhooks are IPv4 only as of 2025
        SocketAddr::V6(_) => false,
    }
}

/// Axum handler for incoming webhook POST requests.
async fn handle_webhook(
    State(state): State<Arc<WebhookState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: String,
) -> StatusCode {
    // Log source IP and check against known Telegram ranges
    if !is_telegram_ip(&addr) {
        warn!(
            source_ip = %addr,
            "webhook request from IP outside known Telegram ranges"
        );
    } else {
        debug!(source_ip = %addr, "webhook request from Telegram IP range");
    }

    // Validate secret token -- fail closed (reject if missing or invalid)
    let provided_token = match headers.get(SECRET_TOKEN_HEADER) {
        Some(value) => match value.to_str() {
            Ok(s) => s,
            Err(_) => {
                warn!(source_ip = %addr, "webhook request with non-UTF8 secret token header");
                return StatusCode::FORBIDDEN;
            }
        },
        None => {
            warn!(source_ip = %addr, "webhook request without secret token header");
            return StatusCode::FORBIDDEN;
        }
    };

    if !validate_secret(&state.secret_token, provided_token) {
        warn!(source_ip = %addr, "webhook request with invalid secret token");
        return StatusCode::FORBIDDEN;
    }

    // Parse the Update JSON
    let update: Update = match serde_json::from_str(&body) {
        Ok(u) => u,
        Err(e) => {
            warn!("failed to parse webhook update JSON: {e}");
            return StatusCode::BAD_REQUEST;
        }
    };

    // Process the update (same logic as the poller)
    process_update(&state, update).await;

    StatusCode::OK
}

/// Process a single Update, extracting actions and forwarding them.
///
/// This reuses the same parsing logic as the poller in `poller.rs`.
async fn process_update(state: &WebhookState, update: Update) {
    // Handle text messages
    if let Some(msg) = update.message {
        if msg.chat.id != state.chat_id {
            debug!(
                from_chat = msg.chat.id,
                expected = state.chat_id,
                "ignoring webhook message from unauthorized chat"
            );
            return;
        }

        if let Some(text) = msg.text {
            let action = format::parse_text_command(&text);

            match &action {
                InboundAction::Unknown(s) => {
                    let help = if s.is_empty() {
                        format::help_text()
                    } else {
                        format!(
                            "Unknown command: `{}`\n\n{}",
                            format::escape_md(s),
                            format::help_text()
                        )
                    };
                    let _ = state
                        .api
                        .send_message(state.chat_id, &help, Some("MarkdownV2"), None, false)
                        .await;
                }
                InboundAction::Command(_) => {
                    if state.action_tx.send(action).await.is_err() {
                        warn!("action channel closed in webhook handler");
                    }
                }
            }
        }
    }

    // Handle callback queries
    if let Some(cb) = update.callback_query {
        let cb_chat_id = cb.message.as_ref().map(|m| m.chat.id);
        if cb_chat_id != Some(state.chat_id) {
            debug!("ignoring webhook callback from unauthorized chat");
            let _ = state.api.answer_callback_query(&cb.id, None).await;
            return;
        }

        if let Some(data) = &cb.data {
            if let Some(action) = format::parse_callback(data) {
                let ack_text = if data.starts_with("approve:") {
                    "Approved"
                } else if data.starts_with("deny:") {
                    "Denied"
                } else {
                    "OK"
                };
                let _ = state
                    .api
                    .answer_callback_query(&cb.id, Some(ack_text))
                    .await;

                if let Some(msg) = &cb.message {
                    let _ = state
                        .api
                        .remove_reply_markup(msg.chat.id, msg.message_id)
                        .await;
                }

                if state.action_tx.send(action).await.is_err() {
                    warn!("action channel closed in webhook handler");
                }
            } else {
                let _ = state
                    .api
                    .answer_callback_query(&cb.id, Some("Invalid action"))
                    .await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Secret token validation tests --

    #[test]
    fn test_webhook_secret_validation_valid() {
        assert!(validate_secret(
            "my-secret-token-123",
            "my-secret-token-123"
        ));
    }

    #[test]
    fn test_webhook_secret_validation_invalid() {
        assert!(!validate_secret("my-secret-token-123", "wrong-token"));
    }

    #[test]
    fn test_webhook_secret_validation_empty() {
        assert!(!validate_secret("my-secret-token", ""));
        assert!(!validate_secret("", "something"));
        assert!(validate_secret("", ""));
    }

    #[test]
    fn test_webhook_secret_validation_similar() {
        // Tokens that differ by only one character must still be rejected
        assert!(!validate_secret("secret-token-aaa", "secret-token-aab"));
        assert!(!validate_secret("secret-token-aaa", "secret-token-aaA"));
    }

    #[test]
    fn test_webhook_secret_validation_length_mismatch() {
        // Different lengths must be rejected
        assert!(!validate_secret("short", "short-extended"));
        assert!(!validate_secret("longer-token", "short"));
    }

    #[test]
    fn test_webhook_secret_constant_time() {
        // This test verifies the function uses ConstantTimeEq by ensuring
        // it produces correct results for various inputs. The actual timing
        // guarantee comes from the `subtle` crate's implementation.
        let secret = "X7kQ9mR2vL5nP8wY3tH6";
        assert!(validate_secret(secret, secret));
        assert!(!validate_secret(secret, "X7kQ9mR2vL5nP8wY3tH7"));
        assert!(!validate_secret(secret, "completely-different-value"));
    }

    // -- Webhook update parsing tests --

    #[test]
    fn test_webhook_update_parsing_message() {
        let json = r#"{
            "update_id": 500,
            "message": {
                "message_id": 100,
                "from": {"id": 42, "first_name": "Alice", "is_bot": false},
                "chat": {"id": 12345, "type": "private"},
                "date": 1700000000,
                "text": "/status"
            }
        }"#;
        let update: Update = serde_json::from_str(json).unwrap();
        assert_eq!(update.update_id, 500);
        let msg = update.message.unwrap();
        assert_eq!(msg.text.unwrap(), "/status");
        assert_eq!(msg.chat.id, 12345);

        // Verify the text command parses to the expected InboundAction
        let action = format::parse_text_command("/status");
        assert!(matches!(action, InboundAction::Command(_)));
    }

    #[test]
    fn test_webhook_update_parsing_callback() {
        let json = r#"{
            "update_id": 501,
            "callback_query": {
                "id": "cb-webhook-1",
                "from": {"id": 42, "first_name": "Alice", "is_bot": false},
                "message": {
                    "message_id": 200,
                    "chat": {"id": 12345, "type": "private"},
                    "date": 1700000000
                },
                "data": "approve:550e8400-e29b-41d4-a716-446655440000"
            }
        }"#;
        let update: Update = serde_json::from_str(json).unwrap();
        let cb = update.callback_query.unwrap();
        assert_eq!(cb.id, "cb-webhook-1");

        let action = format::parse_callback(cb.data.as_deref().unwrap());
        assert!(action.is_some());
    }

    #[test]
    fn test_webhook_update_parsing_inline_query() {
        let json = r#"{
            "update_id": 502,
            "inline_query": {
                "id": "iq-1",
                "from": {"id": 42, "first_name": "Alice", "is_bot": false},
                "query": "search agents",
                "offset": ""
            }
        }"#;
        let update: Update = serde_json::from_str(json).unwrap();
        let iq = update.inline_query.unwrap();
        assert_eq!(iq.id, "iq-1");
        assert_eq!(iq.query, "search agents");
    }

    // -- IP validation tests --

    #[test]
    fn test_telegram_ip_in_range() {
        let addr: SocketAddr = "149.154.167.50:443".parse().unwrap();
        assert!(is_telegram_ip(&addr));

        let addr: SocketAddr = "91.108.4.100:443".parse().unwrap();
        assert!(is_telegram_ip(&addr));
    }

    #[test]
    fn test_non_telegram_ip() {
        let addr: SocketAddr = "192.168.1.1:443".parse().unwrap();
        assert!(!is_telegram_ip(&addr));

        let addr: SocketAddr = "8.8.8.8:443".parse().unwrap();
        assert!(!is_telegram_ip(&addr));
    }

    #[test]
    fn test_ipv6_not_telegram() {
        let addr: SocketAddr = "[::1]:443".parse().unwrap();
        assert!(!is_telegram_ip(&addr));
    }

    // -- Config switch tests --

    #[test]
    fn test_webhook_vs_polling_config_switch() {
        use aegis_types::TelegramConfig;

        // Polling mode (default)
        let polling_config = TelegramConfig {
            bot_token: "123:ABC".into(),
            chat_id: 12345,
            poll_timeout_secs: 30,
            allow_group_commands: false,
            active_hours: None,
            webhook_mode: false,
            webhook_port: None,
            webhook_url: None,
            webhook_secret: None,
            inline_queries_enabled: false,
        };

        let json = serde_json::to_string(&polling_config).unwrap();
        let parsed: TelegramConfig = serde_json::from_str(&json).unwrap();
        assert!(!parsed.webhook_mode);
        assert!(parsed.webhook_port.is_none());
        assert!(parsed.webhook_url.is_none());
        assert!(parsed.webhook_secret.is_none());
        assert!(!parsed.inline_queries_enabled);

        // Webhook mode
        let webhook_config = TelegramConfig {
            bot_token: "123:ABC".into(),
            chat_id: 12345,
            poll_timeout_secs: 30,
            allow_group_commands: false,
            active_hours: None,
            webhook_mode: true,
            webhook_port: Some(8443),
            webhook_url: Some("https://aegis.example.com/webhook".into()),
            webhook_secret: Some("super-secret-token".into()),
            inline_queries_enabled: true,
        };

        let json = serde_json::to_string(&webhook_config).unwrap();
        let parsed: TelegramConfig = serde_json::from_str(&json).unwrap();
        assert!(parsed.webhook_mode);
        assert_eq!(parsed.webhook_port, Some(8443));
        assert_eq!(
            parsed.webhook_url.as_deref(),
            Some("https://aegis.example.com/webhook")
        );
        assert_eq!(parsed.webhook_secret.as_deref(), Some("super-secret-token"));
        assert!(parsed.inline_queries_enabled);
    }

    #[test]
    fn test_webhook_config_backward_compatible() {
        // Old configs without webhook fields must still deserialize
        let json = r#"{
            "bot_token": "123:ABC",
            "chat_id": 12345
        }"#;
        let config: aegis_types::TelegramConfig = serde_json::from_str(json).unwrap();
        assert!(!config.webhook_mode);
        assert!(config.webhook_port.is_none());
        assert!(config.webhook_url.is_none());
        assert!(config.webhook_secret.is_none());
        assert!(!config.inline_queries_enabled);
    }
}
