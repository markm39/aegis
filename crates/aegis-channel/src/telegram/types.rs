//! Serde types for the Telegram Bot API.
//!
//! Only the fields needed by aegis-channel are deserialized. Unknown fields
//! are silently ignored via `#[serde(default)]` and `Option`.

use serde::{Deserialize, Serialize};

/// Generic Telegram API response wrapper.
#[derive(Debug, Deserialize)]
pub struct ApiResponse<T> {
    pub ok: bool,
    pub description: Option<String>,
    pub result: Option<T>,
}

/// A Telegram Update object from `getUpdates` or webhook POST.
#[derive(Debug, Deserialize)]
pub struct Update {
    pub update_id: i64,
    pub message: Option<Message>,
    pub callback_query: Option<CallbackQuery>,
    /// Inline query from a user typing `@bot_name <query>`.
    pub inline_query: Option<InlineQuery>,
    /// Pre-checkout query from the payments flow.
    pub pre_checkout_query: Option<PreCheckoutQuery>,
}

/// A Telegram Message.
#[derive(Debug, Deserialize)]
pub struct Message {
    pub message_id: i64,
    pub from: Option<User>,
    pub chat: Chat,
    pub text: Option<String>,
}

/// A Telegram User.
#[derive(Debug, Deserialize)]
pub struct User {
    pub id: i64,
    pub first_name: String,
    pub username: Option<String>,
}

/// A Telegram Chat.
#[derive(Debug, Deserialize)]
pub struct Chat {
    pub id: i64,
    #[serde(rename = "type")]
    pub chat_type: Option<String>,
}

/// A Telegram callback query from an inline keyboard button press.
#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub id: String,
    pub from: User,
    pub message: Option<Message>,
    pub data: Option<String>,
}

/// Inline keyboard markup for message buttons.
#[derive(Debug, Clone, Serialize)]
pub struct InlineKeyboardMarkup {
    pub inline_keyboard: Vec<Vec<InlineKeyboardButton>>,
}

/// A single inline keyboard button.
#[derive(Debug, Clone, Serialize)]
pub struct InlineKeyboardButton {
    pub text: String,
    pub callback_data: String,
}

/// Sent message result (we only need message_id).
#[derive(Debug, Deserialize)]
pub struct SentMessage {
    pub message_id: i64,
}

// -- Inline query types --

/// A Telegram inline query from a user typing `@bot_name <query>`.
#[derive(Debug, Deserialize)]
pub struct InlineQuery {
    /// Unique identifier for the inline query.
    pub id: String,
    /// Sender of the inline query.
    pub from: User,
    /// Text of the query (may be empty).
    pub query: String,
    /// Offset for pagination of results.
    pub offset: String,
}

/// Result types for `answerInlineQuery`.
///
/// Each variant maps to a Telegram InlineQueryResult type. The `type` and `id`
/// fields are serialized automatically.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InlineQueryResult {
    /// An article result with a title and description.
    Article {
        /// Unique identifier for this result (1-64 bytes).
        id: String,
        /// Title of the result.
        title: String,
        /// Short description of the result.
        description: String,
        /// Content of the message to be sent.
        input_message_content: InputMessageContent,
    },
    /// A photo result.
    Photo {
        /// Unique identifier for this result (1-64 bytes).
        id: String,
        /// URL of the photo.
        photo_url: String,
        /// URL of the thumbnail.
        thumbnail_url: String,
    },
    /// A document result.
    Document {
        /// Unique identifier for this result (1-64 bytes).
        id: String,
        /// Title for the result.
        title: String,
        /// URL of the document.
        document_url: String,
        /// MIME type of the document.
        mime_type: String,
    },
}

/// Content of the message to be sent as a result of an inline query.
#[derive(Debug, Clone, Serialize)]
pub struct InputMessageContent {
    /// Text of the message.
    pub message_text: String,
}

// -- Payment types --

/// A Telegram pre-checkout query from the payments flow.
#[derive(Debug, Deserialize)]
pub struct PreCheckoutQuery {
    /// Unique query identifier.
    pub id: String,
    /// User who sent the query.
    pub from: User,
    /// Three-letter ISO 4217 currency code.
    pub currency: String,
    /// Total price in the smallest units of the currency.
    pub total_amount: i64,
    /// Bot-specified invoice payload.
    pub invoice_payload: String,
}

/// A labeled price for `sendInvoice`.
#[derive(Debug, Clone, Serialize)]
pub struct LabeledPrice {
    /// Portion label.
    pub label: String,
    /// Price in the smallest units of the currency.
    pub amount: i64,
}

/// Parameters for sending an invoice via `sendInvoice`.
#[derive(Debug, Clone, Serialize)]
pub struct Invoice {
    /// Chat ID to send the invoice to.
    pub chat_id: i64,
    /// Product name (1-32 characters).
    pub title: String,
    /// Product description (1-255 characters).
    pub description: String,
    /// Bot-defined invoice payload (1-128 bytes, not displayed to user).
    pub payload: String,
    /// Payment provider token (from @BotFather).
    pub provider_token: String,
    /// Three-letter ISO 4217 currency code.
    pub currency: String,
    /// Breakdown of prices.
    pub prices: Vec<LabeledPrice>,
}

// -- Sticker types --

/// A sticker message to be sent via `sendSticker`.
#[derive(Debug, Clone, Serialize)]
pub struct StickerMessage {
    /// Chat ID to send the sticker to.
    pub chat_id: i64,
    /// Sticker file_id (validated: alphanumeric, dash, underscore; max 256 chars).
    pub sticker: String,
}

/// Maximum length for inline query text after sanitization.
pub const MAX_INLINE_QUERY_LENGTH: usize = 256;

/// Maximum length for a sticker file_id.
pub const MAX_STICKER_FILE_ID_LENGTH: usize = 256;

/// Sanitize inline query text: strip control characters, null bytes, and
/// truncate to [`MAX_INLINE_QUERY_LENGTH`].
///
/// Returns the sanitized string.
pub fn sanitize_inline_query(query: &str) -> String {
    let cleaned: String = query
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_INLINE_QUERY_LENGTH)
        .collect();
    cleaned
}

/// Validate a sticker file_id.
///
/// Sticker file_ids must be alphanumeric, dash, or underscore only, and at
/// most [`MAX_STICKER_FILE_ID_LENGTH`] characters. Returns `Ok(())` on
/// success, or an error description on failure.
pub fn validate_sticker_file_id(file_id: &str) -> Result<(), String> {
    if file_id.is_empty() {
        return Err("sticker file_id cannot be empty".into());
    }
    if file_id.len() > MAX_STICKER_FILE_ID_LENGTH {
        return Err(format!(
            "sticker file_id exceeds maximum length of {} characters",
            MAX_STICKER_FILE_ID_LENGTH
        ));
    }
    if !file_id
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err("sticker file_id must contain only alphanumeric characters, dashes, and underscores".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_update_with_message() {
        let json = r#"{
            "update_id": 123,
            "message": {
                "message_id": 456,
                "from": {"id": 789, "first_name": "Alice", "is_bot": false},
                "chat": {"id": -100123, "type": "private"},
                "date": 1700000000,
                "text": "/status"
            }
        }"#;
        let update: Update = serde_json::from_str(json).unwrap();
        assert_eq!(update.update_id, 123);
        let msg = update.message.unwrap();
        assert_eq!(msg.text.unwrap(), "/status");
        assert_eq!(msg.chat.id, -100123);
    }

    #[test]
    fn deserialize_update_with_callback() {
        let json = r#"{
            "update_id": 124,
            "callback_query": {
                "id": "cb-1",
                "from": {"id": 789, "first_name": "Alice", "is_bot": false},
                "message": {
                    "message_id": 456,
                    "chat": {"id": -100123, "type": "private"},
                    "date": 1700000000
                },
                "data": "approve:550e8400-e29b-41d4-a716-446655440000"
            }
        }"#;
        let update: Update = serde_json::from_str(json).unwrap();
        let cb = update.callback_query.unwrap();
        assert_eq!(cb.id, "cb-1");
        assert!(cb.data.unwrap().starts_with("approve:"));
    }

    #[test]
    fn deserialize_api_response_ok() {
        let json = r#"{"ok": true, "result": [{"update_id": 1}]}"#;
        let resp: ApiResponse<Vec<Update>> = serde_json::from_str(json).unwrap();
        assert!(resp.ok);
        assert_eq!(resp.result.unwrap().len(), 1);
    }

    #[test]
    fn deserialize_api_response_error() {
        let json = r#"{"ok": false, "description": "Unauthorized"}"#;
        let resp: ApiResponse<Vec<Update>> = serde_json::from_str(json).unwrap();
        assert!(!resp.ok);
        assert_eq!(resp.description.unwrap(), "Unauthorized");
    }

    #[test]
    fn serialize_inline_keyboard() {
        let kb = InlineKeyboardMarkup {
            inline_keyboard: vec![vec![
                InlineKeyboardButton {
                    text: "Approve".into(),
                    callback_data: "approve:abc".into(),
                },
                InlineKeyboardButton {
                    text: "Deny".into(),
                    callback_data: "deny:abc".into(),
                },
            ]],
        };
        let json = serde_json::to_string(&kb).unwrap();
        assert!(json.contains("Approve"));
        assert!(json.contains("callback_data"));
    }

    #[test]
    fn deserialize_update_with_inline_query() {
        let json = r#"{
            "update_id": 200,
            "inline_query": {
                "id": "iq-42",
                "from": {"id": 100, "first_name": "Bob", "is_bot": false},
                "query": "search term",
                "offset": ""
            }
        }"#;
        let update: Update = serde_json::from_str(json).unwrap();
        let iq = update.inline_query.unwrap();
        assert_eq!(iq.id, "iq-42");
        assert_eq!(iq.query, "search term");
        assert_eq!(iq.from.id, 100);
    }

    #[test]
    fn deserialize_update_with_pre_checkout_query() {
        let json = r#"{
            "update_id": 300,
            "pre_checkout_query": {
                "id": "pcq-1",
                "from": {"id": 100, "first_name": "Bob", "is_bot": false},
                "currency": "USD",
                "total_amount": 1000,
                "invoice_payload": "sub-monthly"
            }
        }"#;
        let update: Update = serde_json::from_str(json).unwrap();
        let pcq = update.pre_checkout_query.unwrap();
        assert_eq!(pcq.id, "pcq-1");
        assert_eq!(pcq.currency, "USD");
        assert_eq!(pcq.total_amount, 1000);
        assert_eq!(pcq.invoice_payload, "sub-monthly");
    }

    #[test]
    fn serialize_inline_query_result_article() {
        let result = InlineQueryResult::Article {
            id: "1".into(),
            title: "Agent Status".into(),
            description: "View current agent status".into(),
            input_message_content: InputMessageContent {
                message_text: "/status".into(),
            },
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"type\":\"article\""));
        assert!(json.contains("Agent Status"));
        assert!(json.contains("message_text"));
    }

    #[test]
    fn serialize_invoice() {
        let invoice = Invoice {
            chat_id: 12345,
            title: "Pro Plan".into(),
            description: "Monthly subscription".into(),
            payload: "sub-001".into(),
            provider_token: "tok_test".into(),
            currency: "USD".into(),
            prices: vec![LabeledPrice {
                label: "Pro Plan".into(),
                amount: 999,
            }],
        };
        let json = serde_json::to_string(&invoice).unwrap();
        assert!(json.contains("\"currency\":\"USD\""));
        assert!(json.contains("\"amount\":999"));
    }

    #[test]
    fn serialize_sticker_message() {
        let msg = StickerMessage {
            chat_id: 12345,
            sticker: "CAACAgIAAxkBAAI".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("CAACAgIAAxkBAAI"));
    }

    #[test]
    fn sanitize_inline_query_strips_control_chars() {
        let input = "hello\x00world\x01test\n\rfoo";
        let result = sanitize_inline_query(input);
        assert_eq!(result, "helloworldtestfoo");
    }

    #[test]
    fn sanitize_inline_query_truncates_long_input() {
        let input = "a".repeat(500);
        let result = sanitize_inline_query(&input);
        assert_eq!(result.len(), MAX_INLINE_QUERY_LENGTH);
    }

    #[test]
    fn sanitize_inline_query_preserves_normal_text() {
        let input = "normal search query";
        let result = sanitize_inline_query(input);
        assert_eq!(result, input);
    }

    #[test]
    fn validate_sticker_file_id_valid() {
        assert!(validate_sticker_file_id("CAACAgIAAxkBAAI").is_ok());
        assert!(validate_sticker_file_id("abc-def_123").is_ok());
        assert!(validate_sticker_file_id("a").is_ok());
    }

    #[test]
    fn validate_sticker_file_id_rejects_empty() {
        assert!(validate_sticker_file_id("").is_err());
    }

    #[test]
    fn validate_sticker_file_id_rejects_too_long() {
        let long_id = "a".repeat(MAX_STICKER_FILE_ID_LENGTH + 1);
        assert!(validate_sticker_file_id(&long_id).is_err());
    }

    #[test]
    fn validate_sticker_file_id_rejects_injection() {
        assert!(validate_sticker_file_id("../../../etc/passwd").is_err());
        assert!(validate_sticker_file_id("file_id; rm -rf /").is_err());
        assert!(validate_sticker_file_id("id\x00null").is_err());
        assert!(validate_sticker_file_id("id with spaces").is_err());
        assert!(validate_sticker_file_id("<script>alert(1)</script>").is_err());
    }

    #[test]
    fn validate_sticker_file_id_at_boundary_length() {
        let max_id = "a".repeat(MAX_STICKER_FILE_ID_LENGTH);
        assert!(validate_sticker_file_id(&max_id).is_ok());
    }
}
