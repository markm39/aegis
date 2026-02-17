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

/// A Telegram Update object from `getUpdates`.
#[derive(Debug, Deserialize)]
pub struct Update {
    pub update_id: i64,
    pub message: Option<Message>,
    pub callback_query: Option<CallbackQuery>,
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
}
