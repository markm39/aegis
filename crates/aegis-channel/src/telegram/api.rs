//! Raw HTTP calls to the Telegram Bot API.
//!
//! Wraps reqwest for `sendMessage`, `getUpdates`, `answerCallbackQuery`,
//! `answerInlineQuery`, `sendInvoice`, `answerPreCheckoutQuery`,
//! `sendSticker`, `setWebhook`, `deleteWebhook`, and `editMessageReplyMarkup`.
//! All methods return typed responses.

use reqwest::Client;
use serde_json::json;
use tracing::{debug, warn};

use crate::channel::ChannelError;

use super::types::{
    ApiResponse, InlineKeyboardButton, InlineKeyboardMarkup, InlineQueryResult, LabeledPrice,
    SentMessage, Update,
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
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .unwrap_or_else(|_| Client::new()),
            base_url: format!("{}/bot{}", base_url.trim_end_matches('/'), bot_token),
        }
    }

    /// Validate the bot token by calling the `getMe` endpoint.
    ///
    /// Returns the bot's `User` on success, or an API error if the token is invalid.
    pub async fn get_me(&self) -> Result<super::types::User, ChannelError> {
        let resp = self
            .client
            .post(format!("{}/getMe", self.base_url))
            .send()
            .await?;

        let api_resp: ApiResponse<super::types::User> = resp.json().await?;
        if !api_resp.ok {
            let desc = api_resp.description.unwrap_or_default();
            return Err(ChannelError::Api(desc));
        }

        api_resp
            .result
            .ok_or_else(|| ChannelError::Api("getMe returned no result".into()))
    }

    /// Telegram's maximum message length.
    const MAX_MESSAGE_LENGTH: usize = 4096;

    /// Send a text message to a chat.
    ///
    /// Truncates messages exceeding Telegram's 4096-character limit to prevent
    /// silent API rejections. Returns the sent message's ID on success.
    pub async fn send_message(
        &self,
        chat_id: i64,
        text: &str,
        parse_mode: Option<&str>,
        reply_markup: Option<InlineKeyboardMarkup>,
        disable_notification: bool,
    ) -> Result<i64, ChannelError> {
        let text = if text.len() > Self::MAX_MESSAGE_LENGTH {
            warn!(
                len = text.len(),
                "truncating Telegram message to {} chars",
                Self::MAX_MESSAGE_LENGTH
            );
            let max = Self::MAX_MESSAGE_LENGTH - 15;
            let mut end = max;
            while end > 0 && !text.is_char_boundary(end) {
                end -= 1;
            }
            let mut truncated = text[..end].to_string();
            truncated.push_str("\n...(truncated)");
            truncated
        } else {
            text.to_string()
        };

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

        api_resp
            .result
            .map(|m| m.message_id)
            .ok_or_else(|| ChannelError::Api("sendMessage returned ok but no result".into()))
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

    /// Send a photo to a chat using multipart/form-data.
    pub async fn send_photo(
        &self,
        chat_id: i64,
        filename: &str,
        bytes: &[u8],
        caption: Option<&str>,
        disable_notification: bool,
    ) -> Result<i64, ChannelError> {
        use reqwest::multipart;

        let photo_part = multipart::Part::bytes(bytes.to_vec())
            .file_name(filename.to_string())
            .mime_str("image/png")
            .map_err(|e| ChannelError::Other(format!("mime error: {e}")))?;

        let mut form = multipart::Form::new()
            .text("chat_id", chat_id.to_string())
            .part("photo", photo_part);

        if let Some(cap) = caption {
            form = form.text("caption", cap.to_string());
        }
        if disable_notification {
            form = form.text("disable_notification", "true".to_string());
        }

        let resp = self
            .client
            .post(format!("{}/sendPhoto", self.base_url))
            .multipart(form)
            .send()
            .await?;

        let api_resp: ApiResponse<SentMessage> = resp.json().await?;
        if !api_resp.ok {
            let desc = api_resp.description.unwrap_or_default();
            return Err(ChannelError::Api(desc));
        }

        api_resp
            .result
            .map(|m| m.message_id)
            .ok_or_else(|| ChannelError::Api("sendPhoto returned ok but no result".into()))
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

    // -- Inline query support --

    /// Answer an inline query with a list of results.
    ///
    /// Telegram requires a response within 10 seconds of receiving the query.
    /// The `cache_time` parameter controls how long results are cached on
    /// Telegram's servers (in seconds, default 300).
    pub async fn answer_inline_query(
        &self,
        inline_query_id: &str,
        results: &[InlineQueryResult],
        cache_time: Option<u64>,
    ) -> Result<(), ChannelError> {
        let results_json = serde_json::to_value(results)
            .map_err(|e| ChannelError::Other(format!("serialize inline results: {e}")))?;

        let mut body = json!({
            "inline_query_id": inline_query_id,
            "results": results_json,
        });

        if let Some(ct) = cache_time {
            body["cache_time"] = json!(ct);
        }

        let resp = self
            .client
            .post(format!("{}/answerInlineQuery", self.base_url))
            .json(&body)
            .send()
            .await?;

        let api_resp: ApiResponse<bool> = resp.json().await?;
        if !api_resp.ok {
            let desc = api_resp.description.unwrap_or_default();
            warn!("answerInlineQuery failed: {desc}");
            return Err(ChannelError::Api(desc));
        }

        Ok(())
    }

    // -- Payment support --

    /// Send an invoice to a chat.
    ///
    /// The `provider_token` must come from configuration or environment -- never
    /// hardcode payment tokens. Returns the sent message ID on success.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_invoice(
        &self,
        chat_id: i64,
        title: &str,
        description: &str,
        payload: &str,
        provider_token: &str,
        currency: &str,
        prices: &[LabeledPrice],
    ) -> Result<i64, ChannelError> {
        let prices_json = serde_json::to_value(prices)
            .map_err(|e| ChannelError::Other(format!("serialize prices: {e}")))?;

        let body = json!({
            "chat_id": chat_id,
            "title": title,
            "description": description,
            "payload": payload,
            "provider_token": provider_token,
            "currency": currency,
            "prices": prices_json,
        });

        debug!("sendInvoice to chat_id={chat_id}");

        let resp = self
            .client
            .post(format!("{}/sendInvoice", self.base_url))
            .json(&body)
            .send()
            .await?;

        let api_resp: ApiResponse<SentMessage> = resp.json().await?;
        if !api_resp.ok {
            let desc = api_resp.description.unwrap_or_default();
            warn!("sendInvoice failed: {desc}");
            return Err(ChannelError::Api(desc));
        }

        api_resp
            .result
            .map(|m| m.message_id)
            .ok_or_else(|| ChannelError::Api("sendInvoice returned ok but no result".into()))
    }

    /// Answer a pre-checkout query.
    ///
    /// Must be called within 10 seconds of receiving the query. Set `ok` to
    /// `true` to proceed with the order, or `false` with an `error_message`
    /// to reject it.
    pub async fn answer_pre_checkout_query(
        &self,
        pre_checkout_query_id: &str,
        ok: bool,
        error_message: Option<&str>,
    ) -> Result<(), ChannelError> {
        let mut body = json!({
            "pre_checkout_query_id": pre_checkout_query_id,
            "ok": ok,
        });

        if let Some(msg) = error_message {
            body["error_message"] = json!(msg);
        }

        let resp = self
            .client
            .post(format!("{}/answerPreCheckoutQuery", self.base_url))
            .json(&body)
            .send()
            .await?;

        let api_resp: ApiResponse<bool> = resp.json().await?;
        if !api_resp.ok {
            let desc = api_resp.description.unwrap_or_default();
            warn!("answerPreCheckoutQuery failed: {desc}");
            return Err(ChannelError::Api(desc));
        }

        Ok(())
    }

    // -- Sticker support --

    /// Send a sticker to a chat.
    ///
    /// The `sticker` parameter should be a validated file_id. Use
    /// [`super::types::validate_sticker_file_id`] to validate before calling.
    pub async fn send_sticker(
        &self,
        chat_id: i64,
        sticker: &str,
    ) -> Result<i64, ChannelError> {
        // Validate the sticker file_id before sending
        super::types::validate_sticker_file_id(sticker)
            .map_err(|e| ChannelError::Other(format!("invalid sticker file_id: {e}")))?;

        let body = json!({
            "chat_id": chat_id,
            "sticker": sticker,
        });

        debug!("sendSticker to chat_id={chat_id}");

        let resp = self
            .client
            .post(format!("{}/sendSticker", self.base_url))
            .json(&body)
            .send()
            .await?;

        let api_resp: ApiResponse<SentMessage> = resp.json().await?;
        if !api_resp.ok {
            let desc = api_resp.description.unwrap_or_default();
            warn!("sendSticker failed: {desc}");
            return Err(ChannelError::Api(desc));
        }

        api_resp
            .result
            .map(|m| m.message_id)
            .ok_or_else(|| ChannelError::Api("sendSticker returned ok but no result".into()))
    }

    // -- Webhook management --

    /// Register a webhook URL with Telegram.
    ///
    /// When a webhook is set, Telegram will POST updates to the given URL
    /// instead of holding them for `getUpdates`. The `secret_token` is sent
    /// in the `X-Telegram-Bot-Api-Secret-Token` header of each request.
    ///
    /// `allowed_updates` controls which update types Telegram delivers.
    pub async fn set_webhook(
        &self,
        url: &str,
        secret_token: Option<&str>,
        allowed_updates: Option<&[&str]>,
    ) -> Result<(), ChannelError> {
        let mut body = json!({
            "url": url,
        });

        if let Some(token) = secret_token {
            body["secret_token"] = json!(token);
        }

        if let Some(updates) = allowed_updates {
            body["allowed_updates"] = json!(updates);
        }

        let resp = self
            .client
            .post(format!("{}/setWebhook", self.base_url))
            .json(&body)
            .send()
            .await?;

        let api_resp: ApiResponse<bool> = resp.json().await?;
        if !api_resp.ok {
            let desc = api_resp.description.unwrap_or_default();
            warn!("setWebhook failed: {desc}");
            return Err(ChannelError::Api(desc));
        }

        Ok(())
    }

    /// Remove the webhook, returning to `getUpdates` polling mode.
    pub async fn delete_webhook(&self) -> Result<(), ChannelError> {
        let resp = self
            .client
            .post(format!("{}/deleteWebhook", self.base_url))
            .send()
            .await?;

        let api_resp: ApiResponse<bool> = resp.json().await?;
        if !api_resp.ok {
            let desc = api_resp.description.unwrap_or_default();
            warn!("deleteWebhook failed: {desc}");
            return Err(ChannelError::Api(desc));
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

/// Escape text for safe inclusion in Telegram HTML messages.
///
/// Converts `&`, `<`, and `>` to their HTML entity equivalents. This prevents
/// user-supplied text from being interpreted as HTML tags by Telegram's parser.
///
/// Telegram supports a limited subset of HTML tags: `<b>`, `<i>`, `<code>`,
/// `<pre>`, `<a href="...">`, `<u>`, `<s>`, `<tg-spoiler>`.
pub fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + text.len() / 8);
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
    out
}

/// Format text with Telegram-safe HTML markup.
///
/// Accepts a closure that receives an [`HtmlBuilder`] for constructing
/// messages with bold, italic, code, pre-formatted, and hyperlink elements.
/// All text content is automatically HTML-escaped.
///
/// # Example
///
/// ```
/// use aegis_channel::telegram::api::format_html;
///
/// let html = format_html(|b| {
///     b.bold("Alert");
///     b.text(": Agent ");
///     b.code("claude-1");
///     b.text(" exited.");
/// });
/// assert_eq!(html, "<b>Alert</b>: Agent <code>claude-1</code> exited.");
/// ```
pub fn format_html(f: impl FnOnce(&mut HtmlBuilder)) -> String {
    let mut builder = HtmlBuilder::new();
    f(&mut builder);
    builder.finish()
}

/// Builder for constructing Telegram HTML messages.
///
/// All text methods automatically escape HTML entities in user-supplied content.
/// Tag methods (`bold`, `italic`, `code`, `pre`, `link`) wrap content in the
/// appropriate Telegram-supported HTML tags.
pub struct HtmlBuilder {
    buf: String,
}

impl HtmlBuilder {
    fn new() -> Self {
        Self {
            buf: String::with_capacity(256),
        }
    }

    /// Append plain text (HTML-escaped).
    pub fn text(&mut self, s: &str) -> &mut Self {
        self.buf.push_str(&escape_html(s));
        self
    }

    /// Append bold text: `<b>text</b>`.
    pub fn bold(&mut self, s: &str) -> &mut Self {
        self.buf.push_str("<b>");
        self.buf.push_str(&escape_html(s));
        self.buf.push_str("</b>");
        self
    }

    /// Append italic text: `<i>text</i>`.
    pub fn italic(&mut self, s: &str) -> &mut Self {
        self.buf.push_str("<i>");
        self.buf.push_str(&escape_html(s));
        self.buf.push_str("</i>");
        self
    }

    /// Append inline code: `<code>text</code>`.
    pub fn code(&mut self, s: &str) -> &mut Self {
        self.buf.push_str("<code>");
        self.buf.push_str(&escape_html(s));
        self.buf.push_str("</code>");
        self
    }

    /// Append a pre-formatted block: `<pre>text</pre>`.
    pub fn pre(&mut self, s: &str) -> &mut Self {
        self.buf.push_str("<pre>");
        self.buf.push_str(&escape_html(s));
        self.buf.push_str("</pre>");
        self
    }

    /// Append a hyperlink: `<a href="url">text</a>`.
    ///
    /// Both the URL and text are HTML-escaped.
    pub fn link(&mut self, url: &str, text: &str) -> &mut Self {
        self.buf.push_str("<a href=\"");
        self.buf.push_str(&escape_html(url));
        self.buf.push_str("\">");
        self.buf.push_str(&escape_html(text));
        self.buf.push_str("</a>");
        self
    }

    /// Append a raw string without escaping.
    ///
    /// Use with caution -- only for pre-validated content.
    pub fn raw(&mut self, s: &str) -> &mut Self {
        self.buf.push_str(s);
        self
    }

    fn finish(self) -> String {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::types::{InputMessageContent, Invoice as InvoiceType};

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

    // -- HTML formatting tests --

    #[test]
    fn escape_html_entities() {
        assert_eq!(escape_html("a & b"), "a &amp; b");
        assert_eq!(escape_html("x < y > z"), "x &lt; y &gt; z");
        assert_eq!(escape_html("no specials"), "no specials");
        assert_eq!(escape_html(""), "");
        assert_eq!(
            escape_html("<script>alert('xss')</script>"),
            "&lt;script&gt;alert('xss')&lt;/script&gt;"
        );
    }

    #[test]
    fn format_html_basic_tags() {
        let result = format_html(|b| {
            b.bold("Alert");
            b.text(": ");
            b.italic("warning");
            b.text(" in ");
            b.code("main.rs");
        });
        assert_eq!(
            result,
            "<b>Alert</b>: <i>warning</i> in <code>main.rs</code>"
        );
    }

    #[test]
    fn format_html_pre_block() {
        let result = format_html(|b| {
            b.pre("fn main() {\n    println!(\"hello\");\n}");
        });
        assert_eq!(
            result,
            "<pre>fn main() {\n    println!(\"hello\");\n}</pre>"
        );
    }

    #[test]
    fn format_html_link() {
        let result = format_html(|b| {
            b.text("Visit ");
            b.link("https://example.com", "Example");
        });
        assert_eq!(
            result,
            "Visit <a href=\"https://example.com\">Example</a>"
        );
    }

    #[test]
    fn format_html_escapes_user_input() {
        let result = format_html(|b| {
            b.bold("<script>alert(1)</script>");
        });
        assert_eq!(
            result,
            "<b>&lt;script&gt;alert(1)&lt;/script&gt;</b>"
        );
    }

    #[test]
    fn format_html_link_escapes_url() {
        let result = format_html(|b| {
            b.link("https://example.com?a=1&b=2", "test");
        });
        assert!(result.contains("a=1&amp;b=2"));
    }

    // -- Inline query request construction tests --

    #[test]
    fn test_inline_query_answer_article() {
        let results = vec![
            InlineQueryResult::Article {
                id: "1".into(),
                title: "Agent Status".into(),
                description: "Current status of all agents".into(),
                input_message_content: InputMessageContent {
                    message_text: "/status".into(),
                },
            },
            InlineQueryResult::Article {
                id: "2".into(),
                title: "Help".into(),
                description: "Show available commands".into(),
                input_message_content: InputMessageContent {
                    message_text: "/help".into(),
                },
            },
        ];

        let json = serde_json::to_value(&results).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["type"], "article");
        assert_eq!(arr[0]["title"], "Agent Status");
        assert_eq!(
            arr[0]["input_message_content"]["message_text"],
            "/status"
        );
    }

    // -- Payment invoice construction tests --

    #[test]
    fn test_payment_invoice_creation() {
        let invoice = InvoiceType {
            chat_id: 12345,
            title: "Aegis Pro".into(),
            description: "Monthly agent supervision".into(),
            payload: "aegis-pro-monthly-001".into(),
            provider_token: "stripe_test_token".into(),
            currency: "USD".into(),
            prices: vec![
                LabeledPrice {
                    label: "Base plan".into(),
                    amount: 999,
                },
                LabeledPrice {
                    label: "Extra agents (3)".into(),
                    amount: 300,
                },
            ],
        };

        let json = serde_json::to_value(&invoice).unwrap();
        assert_eq!(json["chat_id"], 12345);
        assert_eq!(json["title"], "Aegis Pro");
        assert_eq!(json["currency"], "USD");
        let prices = json["prices"].as_array().unwrap();
        assert_eq!(prices.len(), 2);
        assert_eq!(prices[0]["amount"], 999);
        assert_eq!(prices[1]["label"], "Extra agents (3)");

        // Provider token must come from config, never hardcoded -- this test
        // just verifies the struct serializes correctly. In production, the
        // token value would be read from TelegramConfig or env.
        assert_eq!(json["provider_token"], "stripe_test_token");
    }
}
