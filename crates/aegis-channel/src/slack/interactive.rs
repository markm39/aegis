//! Slack interactive message handler with request signature verification.
//!
//! Handles interactive payloads from Slack (button clicks, select actions)
//! and maps known action IDs to aegis-control commands.
//!
//! Security properties:
//! - Request signatures verified using HMAC-SHA256 with constant-time comparison
//! - Timestamps validated against replay attacks (5-minute window)
//! - All inputs validated before processing

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::channel::ChannelError;

type HmacSha256 = Hmac<Sha256>;

/// Maximum allowed age for a request timestamp in seconds.
/// Requests older than this are rejected to prevent replay attacks.
const MAX_TIMESTAMP_AGE_SECS: u64 = 300; // 5 minutes

/// A parsed Slack interaction payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlackInteraction {
    /// A button was clicked.
    ButtonClick {
        /// The action_id of the clicked button.
        action_id: String,
        /// The value of the clicked button.
        value: String,
        /// The Slack user ID of the user who clicked.
        user_id: String,
    },
    /// A select menu option was chosen.
    SelectAction {
        /// The action_id of the select menu.
        action_id: String,
        /// The value of the selected option.
        selected_value: String,
        /// The Slack user ID of the user who selected.
        user_id: String,
    },
}

/// Mapped aegis command from a Slack interaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappedCommand {
    /// Approve a pending request.
    Approve { request_id: String },
    /// Deny a pending request.
    Deny { request_id: String },
    /// Unknown action (not mapped to an aegis command).
    Unknown { action_id: String },
}

/// Verify a Slack request signature using HMAC-SHA256.
///
/// Computes `HMAC-SHA256("v0:{timestamp}:{body}", signing_secret)` and compares
/// it against the provided signature using constant-time comparison.
///
/// Also rejects requests with timestamps older than 5 minutes to prevent
/// replay attacks.
///
/// # Arguments
/// * `signing_secret` - The Slack app's signing secret
/// * `timestamp` - The `X-Slack-Request-Timestamp` header value
/// * `body` - The raw request body
/// * `signature` - The `X-Slack-Signature` header value (e.g., "v0=abcdef...")
pub fn verify_request_signature(
    signing_secret: &str,
    timestamp: &str,
    body: &str,
    signature: &str,
) -> bool {
    // Validate timestamp format: digits and at most one dot, max 32 chars
    if !validate_timestamp(timestamp) {
        return false;
    }

    // Check for replay attack: reject timestamps older than 5 minutes
    if let Ok(ts) = timestamp.parse::<u64>() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now.saturating_sub(ts) > MAX_TIMESTAMP_AGE_SECS {
            return false;
        }
    } else {
        // Non-numeric timestamp (after dot validation) -- reject
        return false;
    }

    // Compute HMAC-SHA256 of "v0:{timestamp}:{body}"
    let sig_basestring = format!("v0:{timestamp}:{body}");

    let mut mac = match HmacSha256::new_from_slice(signing_secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(sig_basestring.as_bytes());
    let result = mac.finalize();
    let computed = hex::encode(result.into_bytes());
    let expected = format!("v0={computed}");

    // Constant-time comparison to prevent timing attacks
    let expected_bytes = expected.as_bytes();
    let signature_bytes = signature.as_bytes();

    if expected_bytes.len() != signature_bytes.len() {
        // Burn the same time even on length mismatch
        let _ = expected_bytes.ct_eq(expected_bytes);
        return false;
    }

    expected_bytes.ct_eq(signature_bytes).into()
}

/// Validate a Slack timestamp string.
///
/// Valid Slack timestamps contain only digits and optionally one dot,
/// and are at most 32 characters long.
pub fn validate_timestamp(ts: &str) -> bool {
    if ts.is_empty() || ts.len() > 32 {
        return false;
    }
    let mut dot_count = 0;
    for c in ts.chars() {
        if c == '.' {
            dot_count += 1;
            if dot_count > 1 {
                return false;
            }
        } else if !c.is_ascii_digit() {
            return false;
        }
    }
    true
}

/// Parse an interaction payload JSON into a typed `SlackInteraction`.
///
/// Expects the standard Slack interaction payload format with a `type` field
/// and an `actions` array.
pub fn parse_interaction(payload_json: &str) -> Result<SlackInteraction, ChannelError> {
    let payload: serde_json::Value =
        serde_json::from_str(payload_json).map_err(|e| ChannelError::Api(e.to_string()))?;

    let user_id = payload
        .pointer("/user/id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let actions = payload
        .get("actions")
        .and_then(|v| v.as_array())
        .ok_or_else(|| ChannelError::Api("missing actions array in interaction payload".into()))?;

    let action = actions
        .first()
        .ok_or_else(|| ChannelError::Api("empty actions array in interaction payload".into()))?;

    let action_type = action.get("type").and_then(|v| v.as_str()).unwrap_or("");

    let action_id = action
        .get("action_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    match action_type {
        "button" => {
            let value = action
                .get("value")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Ok(SlackInteraction::ButtonClick {
                action_id,
                value,
                user_id,
            })
        }
        "static_select" => {
            let selected_value = action
                .pointer("/selected_option/value")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Ok(SlackInteraction::SelectAction {
                action_id,
                selected_value,
                user_id,
            })
        }
        _ => Err(ChannelError::Api(format!(
            "unsupported interaction type: {action_type}"
        ))),
    }
}

/// Map a Slack interaction to an aegis command based on action_id conventions.
///
/// Known action_id patterns:
/// - `aegis_approve_{request_id}` -> `MappedCommand::Approve`
/// - `aegis_deny_{request_id}` -> `MappedCommand::Deny`
pub fn map_interaction_to_command(interaction: &SlackInteraction) -> MappedCommand {
    let action_id = match interaction {
        SlackInteraction::ButtonClick { action_id, .. } => action_id,
        SlackInteraction::SelectAction { action_id, .. } => action_id,
    };

    if let Some(request_id) = action_id.strip_prefix("aegis_approve_") {
        MappedCommand::Approve {
            request_id: request_id.to_string(),
        }
    } else if let Some(request_id) = action_id.strip_prefix("aegis_deny_") {
        MappedCommand::Deny {
            request_id: request_id.to_string(),
        }
    } else {
        MappedCommand::Unknown {
            action_id: action_id.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_signature_verification() {
        // Compute the expected signature manually for a known input
        let secret = "test_signing_secret_123";
        let body = r#"{"type":"block_actions","user":{"id":"U123"}}"#;

        // Use a timestamp that is "now" to avoid replay rejection
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let timestamp = now.to_string();

        // Compute expected signature
        let sig_basestring = format!("v0:{timestamp}:{body}");
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(sig_basestring.as_bytes());
        let result = mac.finalize();
        let hex_sig = hex::encode(result.into_bytes());
        let signature = format!("v0={hex_sig}");

        // Valid signature should pass
        assert!(verify_request_signature(
            secret, &timestamp, body, &signature
        ));

        // Wrong signature should fail
        assert!(!verify_request_signature(
            secret,
            &timestamp,
            body,
            "v0=0000000000000000000000000000000000000000000000000000000000000000"
        ));

        // Wrong secret should fail
        assert!(!verify_request_signature(
            "wrong_secret",
            &timestamp,
            body,
            &signature
        ));
    }

    #[test]
    fn test_replay_attack_prevention() {
        let secret = "test_secret";
        let body = "test body";

        // Timestamp from 10 minutes ago
        let old_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(600); // 10 minutes ago
        let old_timestamp = old_ts.to_string();

        // Compute a valid signature for the old timestamp
        let sig_basestring = format!("v0:{old_timestamp}:{body}");
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(sig_basestring.as_bytes());
        let result = mac.finalize();
        let hex_sig = hex::encode(result.into_bytes());
        let signature = format!("v0={hex_sig}");

        // Should be rejected because timestamp is too old
        assert!(!verify_request_signature(
            secret,
            &old_timestamp,
            body,
            &signature
        ));
    }

    #[test]
    fn test_signature_constant_time() {
        // Verify that the function uses constant-time comparison by checking
        // that correct results are produced for similar inputs. The actual
        // timing guarantee comes from the `subtle` crate's ConstantTimeEq.
        let secret = "constant_time_test_secret";
        let body = "test body";
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let timestamp = now.to_string();

        let sig_basestring = format!("v0:{timestamp}:{body}");
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(sig_basestring.as_bytes());
        let result = mac.finalize();
        let hex_sig = hex::encode(result.into_bytes());
        let valid_sig = format!("v0={hex_sig}");

        // Valid signature passes
        assert!(verify_request_signature(
            secret, &timestamp, body, &valid_sig
        ));

        // Signature with one bit flipped fails
        let mut bad_bytes: Vec<u8> = valid_sig.bytes().collect();
        if let Some(last) = bad_bytes.last_mut() {
            *last ^= 1;
        }
        let bad_sig = String::from_utf8(bad_bytes).unwrap();
        assert!(!verify_request_signature(
            secret, &timestamp, body, &bad_sig
        ));

        // Completely different signature fails
        assert!(!verify_request_signature(
            secret,
            &timestamp,
            body,
            "v0=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        ));
    }

    #[test]
    fn test_timestamp_validation() {
        // Valid Slack timestamps
        assert!(validate_timestamp("1531420618"));
        assert!(validate_timestamp("1531420618.000123"));
        assert!(validate_timestamp("0"));

        // Invalid timestamps
        assert!(!validate_timestamp(""));
        assert!(!validate_timestamp("abc"));
        assert!(!validate_timestamp("1531420618.000.123")); // double dot
        assert!(!validate_timestamp("1531420618; rm -rf /")); // injection
        assert!(!validate_timestamp(&"9".repeat(33))); // too long
    }

    #[test]
    fn test_interactive_handler_maps_to_command() {
        let interaction = SlackInteraction::ButtonClick {
            action_id: "aegis_approve_550e8400-e29b-41d4-a716-446655440000".to_string(),
            value: "approve".to_string(),
            user_id: "U12345".to_string(),
        };

        let cmd = map_interaction_to_command(&interaction);
        assert_eq!(
            cmd,
            MappedCommand::Approve {
                request_id: "550e8400-e29b-41d4-a716-446655440000".to_string()
            }
        );

        let deny_interaction = SlackInteraction::ButtonClick {
            action_id: "aegis_deny_550e8400-e29b-41d4-a716-446655440000".to_string(),
            value: "deny".to_string(),
            user_id: "U12345".to_string(),
        };

        let cmd = map_interaction_to_command(&deny_interaction);
        assert_eq!(
            cmd,
            MappedCommand::Deny {
                request_id: "550e8400-e29b-41d4-a716-446655440000".to_string()
            }
        );
    }

    #[test]
    fn test_unknown_action_mapping() {
        let interaction = SlackInteraction::ButtonClick {
            action_id: "custom_action".to_string(),
            value: "val".to_string(),
            user_id: "U12345".to_string(),
        };

        let cmd = map_interaction_to_command(&interaction);
        assert_eq!(
            cmd,
            MappedCommand::Unknown {
                action_id: "custom_action".to_string()
            }
        );
    }

    #[test]
    fn test_parse_button_interaction() {
        let payload = r#"{
            "type": "block_actions",
            "user": {"id": "U12345", "name": "alice"},
            "actions": [{
                "type": "button",
                "action_id": "aegis_approve_abc123",
                "value": "approve_val"
            }]
        }"#;

        let result = parse_interaction(payload).unwrap();
        match result {
            SlackInteraction::ButtonClick {
                action_id,
                value,
                user_id,
            } => {
                assert_eq!(action_id, "aegis_approve_abc123");
                assert_eq!(value, "approve_val");
                assert_eq!(user_id, "U12345");
            }
            _ => panic!("expected ButtonClick"),
        }
    }

    #[test]
    fn test_parse_select_interaction() {
        let payload = r#"{
            "type": "block_actions",
            "user": {"id": "U67890", "name": "bob"},
            "actions": [{
                "type": "static_select",
                "action_id": "agent_select",
                "selected_option": {
                    "value": "agent-1"
                }
            }]
        }"#;

        let result = parse_interaction(payload).unwrap();
        match result {
            SlackInteraction::SelectAction {
                action_id,
                selected_value,
                user_id,
            } => {
                assert_eq!(action_id, "agent_select");
                assert_eq!(selected_value, "agent-1");
                assert_eq!(user_id, "U67890");
            }
            _ => panic!("expected SelectAction"),
        }
    }

    #[test]
    fn test_parse_invalid_interaction() {
        let result = parse_interaction("not json");
        assert!(result.is_err());

        let result = parse_interaction(r#"{"type": "block_actions"}"#);
        assert!(result.is_err());
    }

    #[test]
    fn test_select_action_maps_to_command() {
        let interaction = SlackInteraction::SelectAction {
            action_id: "aegis_approve_req-42".to_string(),
            selected_value: "something".to_string(),
            user_id: "U12345".to_string(),
        };

        let cmd = map_interaction_to_command(&interaction);
        assert_eq!(
            cmd,
            MappedCommand::Approve {
                request_id: "req-42".to_string()
            }
        );
    }
}
