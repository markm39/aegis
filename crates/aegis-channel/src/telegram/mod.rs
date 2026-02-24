//! Telegram Bot API channel implementation.
//!
//! Implements the [`Channel`] trait using Telegram's Bot API with
//! long-polling for inbound messages and direct HTTP calls for outbound.

pub mod api;
pub mod poller;
pub mod types;
pub mod webhook;

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{mpsc, watch};
use tracing::info;

use aegis_types::TelegramConfig;

use crate::channel::{
    Channel, ChannelCapabilities, ChannelError, InboundAction, OutboundMessage, OutboundPhoto,
};

use self::api::{build_keyboard, TelegramApi};

/// Telegram channel implementation.
///
/// Spawns a background poller task on construction. Inbound actions
/// are received via an internal mpsc channel.
pub struct TelegramChannel {
    api: Arc<TelegramApi>,
    config: TelegramConfig,
    action_rx: mpsc::Receiver<InboundAction>,
    cancel_tx: watch::Sender<bool>,
}

impl TelegramChannel {
    /// Create a new Telegram channel and start the background poller.
    ///
    /// The poller task runs on the current tokio runtime.
    pub fn new(config: TelegramConfig) -> Self {
        Self::with_api(TelegramApi::new(&config.bot_token), config)
    }

    /// Create with a custom API client (for testing with wiremock).
    pub fn with_api(api: TelegramApi, config: TelegramConfig) -> Self {
        let api = Arc::new(api);
        let (action_tx, action_rx) = mpsc::channel(64);
        let (cancel_tx, cancel_rx) = watch::channel(false);

        // Spawn the poller
        let poller_api = Arc::clone(&api);
        let chat_id = config.chat_id;
        let poll_timeout = config.poll_timeout_secs;
        tokio::spawn(async move {
            poller::poll_loop(poller_api, chat_id, poll_timeout, action_tx, cancel_rx).await;
        });

        Self {
            api,
            config,
            action_rx,
            cancel_tx,
        }
    }

    /// Send the shutdown signal to the poller.
    pub fn shutdown(&self) {
        let _ = self.cancel_tx.send(true);
    }
}

impl Drop for TelegramChannel {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[async_trait]
impl Channel for TelegramChannel {
    async fn send(&self, message: OutboundMessage) -> Result<(), ChannelError> {
        let markup = if message.buttons.is_empty() {
            None
        } else {
            Some(build_keyboard(&message.buttons))
        };

        self.api
            .send_message(
                self.config.chat_id,
                &message.text,
                Some("MarkdownV2"),
                markup,
                message.silent,
            )
            .await?;

        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<InboundAction>, ChannelError> {
        // Non-blocking try_recv -- the poller feeds actions in the background
        match self.action_rx.try_recv() {
            Ok(action) => Ok(Some(action)),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => Err(ChannelError::Shutdown),
        }
    }

    fn name(&self) -> &str {
        "Telegram"
    }

    async fn send_photo(&self, photo: OutboundPhoto) -> Result<(), ChannelError> {
        self.api
            .send_photo(
                self.config.chat_id,
                &photo.filename,
                &photo.bytes,
                photo.caption.as_deref(),
                photo.silent,
            )
            .await?;
        Ok(())
    }

    async fn send_typing(&self) -> Result<(), ChannelError> {
        self.api
            .send_chat_action(self.config.chat_id, "typing")
            .await
    }

    async fn send_with_id(&self, message: OutboundMessage) -> Result<Option<String>, ChannelError> {
        let markup = if message.buttons.is_empty() {
            None
        } else {
            Some(build_keyboard(&message.buttons))
        };

        let msg_id = self
            .api
            .send_message(
                self.config.chat_id,
                &message.text,
                Some("MarkdownV2"),
                markup,
                message.silent,
            )
            .await?;

        Ok(Some(msg_id.to_string()))
    }

    async fn edit_message(&self, message_id: &str, new_text: &str) -> Result<(), ChannelError> {
        let msg_id: i64 = message_id
            .parse()
            .map_err(|_| ChannelError::Other(format!("invalid message_id: {message_id}")))?;

        self.api
            .edit_message_text(self.config.chat_id, msg_id, new_text, Some("MarkdownV2"))
            .await
    }

    async fn delete_message(&self, message_id: &str) -> Result<(), ChannelError> {
        let msg_id: i64 = message_id
            .parse()
            .map_err(|_| ChannelError::Other(format!("invalid message_id: {message_id}")))?;

        self.api.delete_message(self.config.chat_id, msg_id).await
    }

    async fn react(&self, message_id: &str, emoji: &str) -> Result<(), ChannelError> {
        let msg_id: i64 = message_id
            .parse()
            .map_err(|_| ChannelError::Other(format!("invalid message_id: {message_id}")))?;

        self.api
            .set_message_reaction(self.config.chat_id, msg_id, emoji)
            .await
    }

    async fn send_to_thread(
        &self,
        thread_id: &str,
        message: OutboundMessage,
    ) -> Result<(), ChannelError> {
        let tid: i64 = thread_id
            .parse()
            .map_err(|_| ChannelError::Other(format!("invalid thread_id: {thread_id}")))?;

        let markup = if message.buttons.is_empty() {
            None
        } else {
            Some(build_keyboard(&message.buttons))
        };

        self.api
            .send_message_to_thread(
                self.config.chat_id,
                tid,
                &message.text,
                Some("MarkdownV2"),
                markup,
                message.silent,
            )
            .await?;

        Ok(())
    }

    fn capabilities(&self) -> ChannelCapabilities {
        ChannelCapabilities {
            typing_indicators: true,
            message_editing: true,
            message_deletion: true,
            reactions: true,
            threads: true,
            presence: false,
            rich_media: true,
        }
    }
}

/// Send a startup announcement message.
pub async fn send_startup(api: &TelegramApi, chat_id: i64, agent_name: &str) {
    let text = format!(
        "*Aegis Pilot Started*\n\n\
         Agent `{}` is now supervised\\.\n\
         Send /help for available commands\\.",
        crate::format::escape_md(agent_name),
    );
    match api
        .send_message(chat_id, &text, Some("MarkdownV2"), None, false)
        .await
    {
        Ok(_) => info!("startup message sent to Telegram"),
        Err(e) => tracing::warn!("failed to send startup message: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::{matchers, Mock, MockServer, ResponseTemplate};

    /// Helper: create a TelegramChannel backed by a mock server.
    async fn channel_for_mock(server: &MockServer) -> TelegramChannel {
        let api = TelegramApi::with_base_url("test-token", &server.uri());
        let config = TelegramConfig {
            bot_token: "test-token".into(),
            chat_id: 12345,
            poll_timeout_secs: 0,
            allow_group_commands: false,
            active_hours: None,
            webhook_mode: false,
            webhook_port: None,
            webhook_url: None,
            webhook_secret: None,
            inline_queries_enabled: false,
        };
        TelegramChannel::with_api(api, config)
    }

    #[test]
    fn telegram_capabilities_reports_all_features() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let server = MockServer::start().await;

            // Mock getUpdates so the poller does not error
            Mock::given(matchers::method("POST"))
                .and(matchers::path_regex(r"/bot.*/getUpdates"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(json!({"ok": true, "result": []})),
                )
                .mount(&server)
                .await;

            let channel = channel_for_mock(&server).await;
            let caps = channel.capabilities();

            assert!(caps.typing_indicators);
            assert!(caps.message_editing);
            assert!(caps.message_deletion);
            assert!(caps.reactions);
            assert!(caps.threads);
            assert!(!caps.presence);
            assert!(caps.rich_media);
        });
    }

    #[tokio::test]
    async fn send_with_id_returns_message_id() {
        let server = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path_regex(r"/bot.*/getUpdates"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"ok": true, "result": []})),
            )
            .mount(&server)
            .await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path_regex(r"/bot.*/sendMessage"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"ok": true, "result": {"message_id": 42}})),
            )
            .mount(&server)
            .await;

        let channel = channel_for_mock(&server).await;
        let msg = OutboundMessage::text("test");
        let result = channel.send_with_id(msg).await.unwrap();
        assert_eq!(result, Some("42".to_string()));
    }

    #[tokio::test]
    async fn edit_message_invalid_id_returns_error() {
        let server = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path_regex(r"/bot.*/getUpdates"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"ok": true, "result": []})),
            )
            .mount(&server)
            .await;

        let channel = channel_for_mock(&server).await;
        let err = channel
            .edit_message("not-a-number", "new text")
            .await
            .unwrap_err();
        match err {
            ChannelError::Other(msg) => assert!(msg.contains("invalid message_id")),
            other => panic!("expected Other error, got {other}"),
        }
    }

    #[tokio::test]
    async fn delete_message_invalid_id_returns_error() {
        let server = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path_regex(r"/bot.*/getUpdates"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"ok": true, "result": []})),
            )
            .mount(&server)
            .await;

        let channel = channel_for_mock(&server).await;
        let err = channel.delete_message("abc").await.unwrap_err();
        match err {
            ChannelError::Other(msg) => assert!(msg.contains("invalid message_id")),
            other => panic!("expected Other error, got {other}"),
        }
    }

    #[tokio::test]
    async fn react_invalid_id_returns_error() {
        let server = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path_regex(r"/bot.*/getUpdates"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"ok": true, "result": []})),
            )
            .mount(&server)
            .await;

        let channel = channel_for_mock(&server).await;
        let err = channel.react("xyz", "thumbs_up").await.unwrap_err();
        match err {
            ChannelError::Other(msg) => assert!(msg.contains("invalid message_id")),
            other => panic!("expected Other error, got {other}"),
        }
    }

    #[tokio::test]
    async fn send_to_thread_invalid_id_returns_error() {
        let server = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path_regex(r"/bot.*/getUpdates"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"ok": true, "result": []})),
            )
            .mount(&server)
            .await;

        let channel = channel_for_mock(&server).await;
        let msg = OutboundMessage::text("test");
        let err = channel.send_to_thread("bad", msg).await.unwrap_err();
        match err {
            ChannelError::Other(m) => assert!(m.contains("invalid thread_id")),
            other => panic!("expected Other error, got {other}"),
        }
    }
}
