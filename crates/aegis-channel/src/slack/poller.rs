//! Slack inbound message polling via `conversations.history` API.
//!
//! Periodically fetches new messages from a Slack channel and returns
//! the latest unprocessed user message for command parsing.

use reqwest::Client;
use serde::Deserialize;
use tracing::{debug, warn};

use crate::channel::ChannelError;

const API_BASE: &str = "https://slack.com/api";

/// A message from the Slack conversations.history response.
#[derive(Debug, Deserialize)]
struct SlackMessage {
    /// Message text content.
    #[serde(default)]
    text: String,
    /// Timestamp serving as unique message ID.
    ts: String,
    /// Present if the message was sent by a bot.
    #[serde(default)]
    bot_id: Option<String>,
    /// Message subtype (e.g., "bot_message", "channel_join").
    #[serde(default)]
    subtype: Option<String>,
}

/// Response from the Slack conversations.history API.
#[derive(Debug, Deserialize)]
struct HistoryResponse {
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    messages: Vec<SlackMessage>,
}

/// Polls a Slack channel for new inbound user messages.
pub struct SlackPoller {
    client: Client,
    token: String,
    channel_id: String,
    /// Track the timestamp of the last message we have seen.
    last_ts: Option<String>,
}

impl SlackPoller {
    /// Create a new poller for the given channel.
    pub fn new(token: String, channel_id: String) -> Self {
        Self {
            client: Client::new(),
            token,
            channel_id,
            last_ts: None,
        }
    }

    /// Poll for the next unprocessed user message.
    ///
    /// Returns `Ok(Some(text))` if a new user message is found,
    /// `Ok(None)` if there are no new messages, or an error on API failure.
    pub async fn poll(&mut self) -> Result<Option<String>, ChannelError> {
        let mut request = self
            .client
            .get(format!("{API_BASE}/conversations.history"))
            .bearer_auth(&self.token)
            .query(&[("channel", &self.channel_id), ("limit", &"10".to_string())]);

        if let Some(ref ts) = self.last_ts {
            request = request.query(&[("oldest", ts)]);
        }

        let response = request.send().await?;
        let parsed: HistoryResponse = response.json().await?;

        if !parsed.ok {
            let err = parsed.error.unwrap_or_else(|| "unknown error".into());
            warn!(error = %err, "conversations.history failed");
            return Err(ChannelError::Api(err));
        }

        // Messages come newest-first. We want the oldest unprocessed user message.
        // Filter out bot messages and subtypes (joins, leaves, etc.).
        let user_messages: Vec<&SlackMessage> = parsed
            .messages
            .iter()
            .filter(|m| m.bot_id.is_none() && m.subtype.is_none())
            .collect();

        // Find the oldest message that is strictly newer than our last_ts.
        // Since messages are newest-first, iterate in reverse for chronological order.
        for msg in user_messages.iter().rev() {
            let dominated_by_last = self
                .last_ts
                .as_ref()
                .is_some_and(|last| msg.ts <= *last);

            if dominated_by_last {
                continue;
            }

            debug!(ts = %msg.ts, text = %msg.text, "received Slack user message");
            self.last_ts = Some(msg.ts.clone());
            return Ok(Some(msg.text.clone()));
        }

        // Update last_ts to the newest message timestamp even if all were filtered,
        // so we don't re-fetch the same batch.
        if let Some(newest) = parsed.messages.first() {
            if self
                .last_ts
                .as_ref()
                .is_none_or(|last| newest.ts > *last)
            {
                self.last_ts = Some(newest.ts.clone());
            }
        }

        Ok(None)
    }
}
