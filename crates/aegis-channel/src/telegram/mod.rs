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

use crate::channel::{Channel, ChannelError, InboundAction, OutboundMessage, OutboundPhoto};

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
