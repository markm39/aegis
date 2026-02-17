//! Raw HTTP calls to the Telegram Bot API.
//!
//! Wraps reqwest for `sendMessage`, `getUpdates`, `answerCallbackQuery`,
//! and `editMessageReplyMarkup`. All methods return typed responses.

use reqwest::Client;
use serde_json::json;
use tracing::{debug, warn};

use crate::channel::ChannelError;

use super::types::{
    ApiResponse, InlineKeyboardButton, InlineKeyboardMarkup, SentMessage, Update,
};

/// Low-level Telegram Bot API client.
pub struct TelegramApi {
    client: Client,
    base_url: String,
}

impl TelegramApi {
    /// Create a new API client for the given bot token.
    pub fn new(bot_token: &str) -> Self {
        Self::with_base_url(bot_token, "https://api.telegram.org")
    }

    /// Create a new API client with a custom base URL (for testing).
    pub fn with_base_url(bot_token: &str, base_url: &str) -> Self {
        Self {
            client: Client::new(),
            base_url: format!("{}/bot{}", base_url.trim_end_matches('/'), bot_token),
        }
    }

    /// Send a text message to a chat.
    ///
    /// Returns the sent message's ID on success.
    pub async fn send_message(
        &self,
        chat_id: i64,
        text: &str,
        parse_mode: Option<&str>,
        reply_markup: Option<InlineKeyboardMarkup>,
        disable_notification: bool,
    ) -> Result<i64, ChannelError> {
        let mut body = json!({
            "chat_id": chat_id,
            "text": text,
        });

        if let Some(mode) = parse_mode {
            body["parse_mode"] = json!(mode);
        }
        if let Some(markup) = reply_markup {
            body["reply_markup"] = serde_json::to_value(markup)
                .map_err(|e| ChannelError::Other(format!("serialize markup: {e}")))?;
        }
        if disable_notification {
            body["disable_notification"] = json!(true);
        }

        debug!("sendMessage to chat_id={chat_id}");

        let resp = self
            .client
            .post(format!("{}/sendMessage", self.base_url))
            .json(&body)
            .send()
            .await?;

        let api_resp: ApiResponse<SentMessage> = resp.json().await?;
        if !api_resp.ok {
            let desc = api_resp.description.unwrap_or_default();
            warn!("sendMessage failed: {desc}");
            return Err(ChannelError::Api(desc));
        }

        Ok(api_resp.result.map(|m| m.message_id).unwrap_or(0))
    }

    /// Long-poll for new updates.
    ///
    /// `offset` should be set to `last_update_id + 1` to acknowledge
    /// previously received updates.
    pub async fn get_updates(
        &self,
        offset: Option<i64>,
        timeout: u64,
    ) -> Result<Vec<Update>, ChannelError> {
        let mut body = json!({
            "timeout": timeout,
            "allowed_updates": ["message", "callback_query"],
        });

        if let Some(off) = offset {
            body["offset"] = json!(off);
        }

        let resp = self
            .client
            .post(format!("{}/getUpdates", self.base_url))
            .json(&body)
            .send()
            .await?;

        let api_resp: ApiResponse<Vec<Update>> = resp.json().await?;
        if !api_resp.ok {
            let desc = api_resp.description.unwrap_or_default();
            warn!("getUpdates failed: {desc}");
            return Err(ChannelError::Api(desc));
        }

        Ok(api_resp.result.unwrap_or_default())
    }

    /// Acknowledge a callback query (dismisses the loading spinner on the button).
    pub async fn answer_callback_query(
        &self,
        callback_query_id: &str,
        text: Option<&str>,
    ) -> Result<(), ChannelError> {
        let mut body = json!({
            "callback_query_id": callback_query_id,
        });

        if let Some(t) = text {
            body["text"] = json!(t);
        }

        let resp = self
            .client
            .post(format!("{}/answerCallbackQuery", self.base_url))
            .json(&body)
            .send()
            .await?;

        let api_resp: ApiResponse<bool> = resp.json().await?;
        if !api_resp.ok {
            let desc = api_resp.description.unwrap_or_default();
            warn!("answerCallbackQuery failed: {desc}");
            return Err(ChannelError::Api(desc));
        }

        Ok(())
    }

    /// Remove inline keyboard buttons from a message (prevents double-tap).
    pub async fn remove_reply_markup(
        &self,
        chat_id: i64,
        message_id: i64,
    ) -> Result<(), ChannelError> {
        let body = json!({
            "chat_id": chat_id,
            "message_id": message_id,
            "reply_markup": {"inline_keyboard": []},
        });

        let resp = self
            .client
            .post(format!("{}/editMessageReplyMarkup", self.base_url))
            .json(&body)
            .send()
            .await?;

        let api_resp: ApiResponse<serde_json::Value> = resp.json().await?;
        if !api_resp.ok {
            let desc = api_resp.description.unwrap_or_default();
            // Not critical -- button might already be gone
            debug!("editMessageReplyMarkup failed: {desc}");
        }

        Ok(())
    }
}

/// Build an `InlineKeyboardMarkup` from button (label, callback_data) pairs.
///
/// Places all buttons on a single row.
pub fn build_keyboard(buttons: &[(String, String)]) -> InlineKeyboardMarkup {
    let row = buttons
        .iter()
        .map(|(text, data)| InlineKeyboardButton {
            text: text.clone(),
            callback_data: data.clone(),
        })
        .collect();

    InlineKeyboardMarkup {
        inline_keyboard: vec![row],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_keyboard_from_buttons() {
        let buttons = vec![
            ("Approve".into(), "approve:abc".into()),
            ("Deny".into(), "deny:abc".into()),
        ];
        let kb = build_keyboard(&buttons);
        assert_eq!(kb.inline_keyboard.len(), 1);
        assert_eq!(kb.inline_keyboard[0].len(), 2);
        assert_eq!(kb.inline_keyboard[0][0].text, "Approve");
        assert_eq!(kb.inline_keyboard[0][1].callback_data, "deny:abc");
    }
}
