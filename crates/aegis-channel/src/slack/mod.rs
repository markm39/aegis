//! Slack channel backend (outbound only, minimal streaming support).

use async_trait::async_trait;
use tracing::warn;

use aegis_types::SlackConfig;

use crate::channel::{Channel, ChannelError, InboundAction, OutboundMessage, OutboundPhoto};
use crate::slack::api::SlackApi;

pub mod api;

pub struct SlackChannel {
    config: SlackConfig,
    api: SlackApi,
}

impl SlackChannel {
    pub fn new(config: SlackConfig) -> Self {
        let api = SlackApi::new(config.bot_token.clone());
        Self { config, api }
    }

    async fn send_streaming(&self, text: &str) -> Result<(), ChannelError> {
        // Create a placeholder message to obtain a thread_ts.
        let thread_ts = self
            .api
            .post_message(&self.config.channel_id, "…", None)
            .await?;
        let Some(thread_ts) = thread_ts else {
            return Err(ChannelError::Api("missing thread_ts".into()));
        };

        let stream_ts = self
            .api
            .start_stream(
                &self.config.channel_id,
                &thread_ts,
                self.config.recipient_team_id.as_deref(),
                self.config.recipient_user_id.as_deref(),
            )
            .await?;

        self.api
            .append_stream(&stream_ts, text, self.config.recipient_team_id.as_deref())
            .await?;

        self.api
            .stop_stream(&stream_ts, None, self.config.recipient_team_id.as_deref())
            .await?;

        Ok(())
    }
}

#[async_trait]
impl Channel for SlackChannel {
    async fn send(&self, message: OutboundMessage) -> Result<(), ChannelError> {
        let text = message.text;
        if self.config.streaming && !text.trim().is_empty() {
            if let Err(e) = self.send_streaming(&text).await {
                warn!("slack streaming failed: {e}, falling back to postMessage");
            } else {
                return Ok(());
            }
        }
        let _ = self
            .api
            .post_message(&self.config.channel_id, &text, None)
            .await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<InboundAction>, ChannelError> {
        Ok(None)
    }

    fn name(&self) -> &str {
        "Slack"
    }

    async fn send_photo(&self, photo: OutboundPhoto) -> Result<(), ChannelError> {
        self.api
            .upload_file(
                &self.config.channel_id,
                &photo.filename,
                &photo.bytes,
                photo.caption.as_deref(),
            )
            .await
    }
}
