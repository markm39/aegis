//! Slack channel backend with full bidirectional messaging.
//!
//! Implements the [`Channel`] trait with support for:
//! - Outbound text messages (with optional streaming via Slack's streaming API)
//! - Inbound message polling via `conversations.history`
//! - Message editing via `chat.update`
//! - Message deletion via `chat.delete`
//! - Emoji reactions via `reactions.add`
//! - Threading via `thread_ts` parameter
//! - File uploads via `files.upload`
//! - Typing indicators (no native Slack support; no-op)
//!
//! # Security
//!
//! - Interactive message signatures verified via HMAC-SHA256 (see `interactive` module)
//! - All channel/timestamp/emoji inputs validated before API calls
//! - Bot token never logged or serialized

use async_trait::async_trait;
use tracing::warn;

use aegis_types::SlackConfig;

use crate::channel::{
    Channel, ChannelCapabilities, ChannelError, InboundAction, OutboundMessage, OutboundPhoto,
};
use crate::slack::api::SlackApi;
use crate::slack::poller::SlackPoller;

pub mod api;
pub mod blocks;
pub mod interactive;
pub mod oauth;
pub mod poller;

/// Slack channel implementing bidirectional messaging via the Slack Web API.
///
/// Sends outbound messages using `chat.postMessage` (with optional streaming),
/// polls for inbound messages via `conversations.history`, and supports
/// editing, deleting, reactions, and threading.
pub struct SlackChannel {
    config: SlackConfig,
    api: SlackApi,
    poller: SlackPoller,
}

impl SlackChannel {
    pub fn new(config: SlackConfig) -> Self {
        let api = SlackApi::new(config.bot_token.clone());
        let poller = SlackPoller::new(config.bot_token.clone(), config.channel_id.clone());
        Self {
            config,
            api,
            poller,
        }
    }

    /// Access the underlying Slack API client.
    pub fn api(&self) -> &SlackApi {
        &self.api
    }

    async fn send_streaming(&self, text: &str) -> Result<(), ChannelError> {
        // Create a placeholder message to obtain a thread_ts.
        let thread_ts = self
            .api
            .post_message(&self.config.channel_id, "\u{2026}", None)
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
        match self.poller.poll().await? {
            Some(text) => Ok(Some(crate::format::parse_text_command(&text))),
            None => Ok(None),
        }
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

    async fn send_typing(&self) -> Result<(), ChannelError> {
        // Slack does not have a public typing indicator API for bots.
        // This is a no-op that succeeds silently.
        Ok(())
    }

    async fn send_with_id(
        &self,
        message: OutboundMessage,
    ) -> Result<Option<String>, ChannelError> {
        let text = message.text;
        let ts = self
            .api
            .post_message(&self.config.channel_id, &text, None)
            .await?;
        Ok(ts)
    }

    async fn edit_message(&self, message_id: &str, new_text: &str) -> Result<(), ChannelError> {
        self.api
            .update_message(&self.config.channel_id, message_id, new_text)
            .await
    }

    async fn delete_message(&self, message_id: &str) -> Result<(), ChannelError> {
        self.api
            .delete_message(&self.config.channel_id, message_id)
            .await
    }

    async fn react(&self, message_id: &str, emoji: &str) -> Result<(), ChannelError> {
        // Strip surrounding colons if present (e.g., ":thumbsup:" -> "thumbsup")
        let emoji_name = emoji
            .strip_prefix(':')
            .and_then(|s| s.strip_suffix(':'))
            .unwrap_or(emoji);

        self.api
            .add_reaction(&self.config.channel_id, message_id, emoji_name)
            .await
    }

    async fn send_to_thread(
        &self,
        thread_id: &str,
        message: OutboundMessage,
    ) -> Result<(), ChannelError> {
        let _ = self
            .api
            .post_message(&self.config.channel_id, &message.text, Some(thread_id))
            .await?;
        Ok(())
    }

    fn capabilities(&self) -> ChannelCapabilities {
        ChannelCapabilities {
            typing_indicators: false, // Slack has no bot typing API
            message_editing: true,
            message_deletion: true,
            reactions: true,
            threads: true,
            presence: false,
            rich_media: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::Channel;

    fn test_config() -> SlackConfig {
        SlackConfig {
            bot_token: "xoxb-test-token".to_string(),
            channel_id: "C0123456789".to_string(),
            recipient_team_id: None,
            recipient_user_id: None,
            streaming: false,
            active_hours: None,
            signing_secret: None,
            oauth_client_id: None,
            interactive_endpoint_port: None,
        }
    }

    #[test]
    fn slack_channel_name() {
        let channel = SlackChannel::new(test_config());
        assert_eq!(channel.name(), "Slack");
    }

    #[test]
    fn slack_capabilities_reports_features() {
        let channel = SlackChannel::new(test_config());
        let caps = channel.capabilities();

        assert!(!caps.typing_indicators);
        assert!(caps.message_editing);
        assert!(caps.message_deletion);
        assert!(caps.reactions);
        assert!(caps.threads);
        assert!(!caps.presence);
        assert!(caps.rich_media);
    }

    #[tokio::test]
    async fn slack_send_typing_succeeds() {
        let channel = SlackChannel::new(test_config());
        // send_typing is a no-op on Slack, should always succeed
        assert!(channel.send_typing().await.is_ok());
    }

    #[test]
    fn slack_react_strips_colons() {
        // Verify colon stripping logic
        let emoji = ":thumbsup:";
        let stripped = emoji
            .strip_prefix(':')
            .and_then(|s| s.strip_suffix(':'))
            .unwrap_or(emoji);
        assert_eq!(stripped, "thumbsup");

        // Without colons, stays the same
        let emoji = "thumbsup";
        let stripped = emoji
            .strip_prefix(':')
            .and_then(|s| s.strip_suffix(':'))
            .unwrap_or(emoji);
        assert_eq!(stripped, "thumbsup");

        // Only leading colon, no stripping
        let emoji = ":thumbsup";
        let stripped = emoji
            .strip_prefix(':')
            .and_then(|s| s.strip_suffix(':'))
            .unwrap_or(emoji);
        assert_eq!(stripped, ":thumbsup");
    }
}
