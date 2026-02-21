//! Slack Web API wrapper for outbound messages, streaming, reactions, and pins.

use reqwest::Client;
use serde::Deserialize;

use crate::channel::ChannelError;
use crate::slack::blocks::Block;

const API_BASE: &str = "https://slack.com/api";

#[derive(Debug, Deserialize)]
struct SlackResponse {
    ok: bool,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PostMessageResponse {
    ok: bool,
    error: Option<String>,
    ts: Option<String>,
}

#[derive(Debug, Deserialize)]
struct StartStreamResponse {
    ok: bool,
    error: Option<String>,
    stream_ts: Option<String>,
}

fn ensure_ok(resp: &SlackResponse) -> Result<(), ChannelError> {
    if resp.ok {
        Ok(())
    } else {
        Err(ChannelError::Api(
            resp.error.clone().unwrap_or_else(|| "unknown error".into()),
        ))
    }
}

pub struct SlackApi {
    client: Client,
    token: String,
}

impl SlackApi {
    pub fn new(token: String) -> Self {
        Self {
            client: Client::new(),
            token,
        }
    }

    pub async fn post_message(
        &self,
        channel: &str,
        text: &str,
        thread_ts: Option<&str>,
    ) -> Result<Option<String>, ChannelError> {
        let mut body = serde_json::json!({
            "channel": channel,
            "text": text,
        });
        if let Some(thread_ts) = thread_ts {
            body["thread_ts"] = serde_json::Value::String(thread_ts.to_string());
        }

        let resp = self
            .client
            .post(format!("{API_BASE}/chat.postMessage"))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await?;

        let parsed: PostMessageResponse = resp.json().await?;
        if !parsed.ok {
            return Err(ChannelError::Api(
                parsed.error.unwrap_or_else(|| "unknown error".into()),
            ));
        }
        Ok(parsed.ts)
    }

    pub async fn start_stream(
        &self,
        channel: &str,
        thread_ts: &str,
        recipient_team_id: Option<&str>,
        recipient_user_id: Option<&str>,
    ) -> Result<String, ChannelError> {
        let mut body = serde_json::json!({
            "channel": channel,
            "thread_ts": thread_ts,
        });
        if let Some(team_id) = recipient_team_id {
            body["recipient_team_id"] = serde_json::Value::String(team_id.to_string());
        }
        if let Some(user_id) = recipient_user_id {
            body["recipient_user_id"] = serde_json::Value::String(user_id.to_string());
        }

        let resp = self
            .client
            .post(format!("{API_BASE}/chat.startStream"))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await?;

        let parsed: StartStreamResponse = resp.json().await?;
        if !parsed.ok {
            return Err(ChannelError::Api(
                parsed.error.unwrap_or_else(|| "unknown error".into()),
            ));
        }
        parsed
            .stream_ts
            .ok_or_else(|| ChannelError::Api("missing stream_ts".into()))
    }

    pub async fn append_stream(
        &self,
        stream_ts: &str,
        text: &str,
        recipient_team_id: Option<&str>,
    ) -> Result<(), ChannelError> {
        let mut body = serde_json::json!({
            "stream_ts": stream_ts,
            "markdown_text": text,
        });
        if let Some(team_id) = recipient_team_id {
            body["recipient_team_id"] = serde_json::Value::String(team_id.to_string());
        }

        let resp = self
            .client
            .post(format!("{API_BASE}/chat.appendStream"))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await?;

        let parsed: SlackResponse = resp.json().await?;
        ensure_ok(&parsed)
    }

    /// Upload a file to a Slack channel using files.upload (v1) API.
    pub async fn upload_file(
        &self,
        channel: &str,
        filename: &str,
        bytes: &[u8],
        title: Option<&str>,
    ) -> Result<(), ChannelError> {
        use reqwest::multipart;

        let file_part =
            multipart::Part::bytes(bytes.to_vec()).file_name(filename.to_string());

        let mut form = multipart::Form::new()
            .text("channels", channel.to_string())
            .part("file", file_part);

        if let Some(t) = title {
            form = form.text("title", t.to_string());
        }

        let resp = self
            .client
            .post(format!("{API_BASE}/files.upload"))
            .bearer_auth(&self.token)
            .multipart(form)
            .send()
            .await?;

        let parsed: SlackResponse = resp.json().await?;
        ensure_ok(&parsed)
    }

    pub async fn stop_stream(
        &self,
        stream_ts: &str,
        final_text: Option<&str>,
        recipient_team_id: Option<&str>,
    ) -> Result<(), ChannelError> {
        let mut body = serde_json::json!({
            "stream_ts": stream_ts,
        });
        if let Some(text) = final_text {
            body["markdown_text"] = serde_json::Value::String(text.to_string());
        }
        if let Some(team_id) = recipient_team_id {
            body["recipient_team_id"] = serde_json::Value::String(team_id.to_string());
        }

        let resp = self
            .client
            .post(format!("{API_BASE}/chat.stopStream"))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await?;

        let parsed: SlackResponse = resp.json().await?;
        ensure_ok(&parsed)
    }

    /// Post a Block Kit message to a channel.
    ///
    /// The `text_fallback` is shown in notifications and clients that
    /// do not support Block Kit.
    pub async fn post_blocks(
        &self,
        channel: &str,
        blocks: &[Block],
        text_fallback: &str,
    ) -> Result<Option<String>, ChannelError> {
        let blocks_json = serde_json::to_value(blocks)
            .map_err(|e| ChannelError::Api(format!("failed to serialize blocks: {e}")))?;

        let body = serde_json::json!({
            "channel": channel,
            "text": text_fallback,
            "blocks": blocks_json,
        });

        let resp = self
            .client
            .post(format!("{API_BASE}/chat.postMessage"))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await?;

        let parsed: PostMessageResponse = resp.json().await?;
        if !parsed.ok {
            return Err(ChannelError::Api(
                parsed.error.unwrap_or_else(|| "unknown error".into()),
            ));
        }
        Ok(parsed.ts)
    }

    /// Add a reaction emoji to a message.
    ///
    /// The `emoji` parameter should be the emoji name without colons
    /// (e.g., "thumbsup", not ":thumbsup:").
    pub async fn add_reaction(
        &self,
        channel: &str,
        timestamp: &str,
        emoji: &str,
    ) -> Result<(), ChannelError> {
        validate_channel(channel)?;
        validate_timestamp(timestamp)?;
        validate_emoji(emoji)?;

        let body = serde_json::json!({
            "channel": channel,
            "timestamp": timestamp,
            "name": emoji,
        });

        let resp = self
            .client
            .post(format!("{API_BASE}/reactions.add"))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await?;

        let parsed: SlackResponse = resp.json().await?;
        ensure_ok(&parsed)
    }

    /// Remove a reaction emoji from a message.
    pub async fn remove_reaction(
        &self,
        channel: &str,
        timestamp: &str,
        emoji: &str,
    ) -> Result<(), ChannelError> {
        validate_channel(channel)?;
        validate_timestamp(timestamp)?;
        validate_emoji(emoji)?;

        let body = serde_json::json!({
            "channel": channel,
            "timestamp": timestamp,
            "name": emoji,
        });

        let resp = self
            .client
            .post(format!("{API_BASE}/reactions.remove"))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await?;

        let parsed: SlackResponse = resp.json().await?;
        ensure_ok(&parsed)
    }

    /// Pin a message in a channel.
    pub async fn pin_message(
        &self,
        channel: &str,
        timestamp: &str,
    ) -> Result<(), ChannelError> {
        validate_channel(channel)?;
        validate_timestamp(timestamp)?;

        let body = serde_json::json!({
            "channel": channel,
            "timestamp": timestamp,
        });

        let resp = self
            .client
            .post(format!("{API_BASE}/pins.add"))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await?;

        let parsed: SlackResponse = resp.json().await?;
        ensure_ok(&parsed)
    }

    /// Unpin a message from a channel.
    pub async fn unpin_message(
        &self,
        channel: &str,
        timestamp: &str,
    ) -> Result<(), ChannelError> {
        validate_channel(channel)?;
        validate_timestamp(timestamp)?;

        let body = serde_json::json!({
            "channel": channel,
            "timestamp": timestamp,
        });

        let resp = self
            .client
            .post(format!("{API_BASE}/pins.remove"))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await?;

        let parsed: SlackResponse = resp.json().await?;
        ensure_ok(&parsed)
    }
}

/// Validate a Slack emoji name.
///
/// Valid emoji names contain only alphanumeric characters, underscores,
/// colons, and hyphens. Maximum length is 64 characters.
pub fn validate_emoji(name: &str) -> Result<(), ChannelError> {
    if name.is_empty() || name.len() > 64 {
        return Err(ChannelError::Api(format!(
            "invalid emoji name: must be 1-64 characters, got {}",
            name.len()
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':' || c == '-')
    {
        return Err(ChannelError::Api(format!(
            "invalid emoji name: contains disallowed characters: {name:?}"
        )));
    }
    Ok(())
}

/// Validate a Slack channel ID.
///
/// Valid channel IDs contain only alphanumeric characters, hyphens, and
/// underscores. Maximum length is 32 characters.
pub fn validate_channel(channel: &str) -> Result<(), ChannelError> {
    if channel.is_empty() || channel.len() > 32 {
        return Err(ChannelError::Api(format!(
            "invalid channel ID: must be 1-32 characters, got {}",
            channel.len()
        )));
    }
    if !channel
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ChannelError::Api(format!(
            "invalid channel ID: contains disallowed characters: {channel:?}"
        )));
    }
    Ok(())
}

/// Validate a Slack message timestamp.
///
/// Valid timestamps contain only digits and at most one dot.
/// Maximum length is 32 characters.
pub fn validate_timestamp(ts: &str) -> Result<(), ChannelError> {
    if ts.is_empty() || ts.len() > 32 {
        return Err(ChannelError::Api(format!(
            "invalid timestamp: must be 1-32 characters, got {}",
            ts.len()
        )));
    }
    let mut dot_count = 0;
    for c in ts.chars() {
        if c == '.' {
            dot_count += 1;
            if dot_count > 1 {
                return Err(ChannelError::Api(
                    "invalid timestamp: multiple dots".into(),
                ));
            }
        } else if !c.is_ascii_digit() {
            return Err(ChannelError::Api(format!(
                "invalid timestamp: contains disallowed characters: {ts:?}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Input validation tests --

    #[test]
    fn test_emoji_name_validation() {
        // Valid emoji names
        assert!(validate_emoji("thumbsup").is_ok());
        assert!(validate_emoji("white_check_mark").is_ok());
        assert!(validate_emoji(":custom_emoji:").is_ok());
        assert!(validate_emoji("flag-us").is_ok());
        assert!(validate_emoji("a").is_ok());

        // Invalid emoji names
        assert!(validate_emoji("").is_err());
        assert!(validate_emoji(&"a".repeat(65)).is_err()); // too long
        assert!(validate_emoji("emoji name").is_err()); // space
        assert!(validate_emoji("emoji<script>").is_err()); // injection
        assert!(validate_emoji("emoji\n").is_err()); // newline
        assert!(validate_emoji("emoji/path").is_err()); // slash
    }

    #[test]
    fn test_channel_validation() {
        // Valid channel IDs
        assert!(validate_channel("C0123456789").is_ok());
        assert!(validate_channel("my-channel").is_ok());
        assert!(validate_channel("test_channel").is_ok());

        // Invalid channel IDs
        assert!(validate_channel("").is_err());
        assert!(validate_channel(&"C".repeat(33)).is_err()); // too long
        assert!(validate_channel("chan nel").is_err()); // space
        assert!(validate_channel("channel<>").is_err()); // special chars
    }

    #[test]
    fn test_timestamp_validation() {
        // Valid timestamps
        assert!(validate_timestamp("1531420618").is_ok());
        assert!(validate_timestamp("1531420618.000200").is_ok());
        assert!(validate_timestamp("0").is_ok());

        // Invalid timestamps
        assert!(validate_timestamp("").is_err());
        assert!(validate_timestamp(&"9".repeat(33)).is_err()); // too long
        assert!(validate_timestamp("abc").is_err()); // non-numeric
        assert!(validate_timestamp("1531420618.000.200").is_err()); // double dot
        assert!(validate_timestamp("1531420618; rm -rf /").is_err()); // injection
    }

    #[test]
    fn test_add_reaction_api_call() {
        // Verify that add_reaction validates inputs before making the API call.
        // We test the validation layer; the actual HTTP call requires a mock server.
        let api = SlackApi::new("xoxb-test-token".to_string());

        // Test that invalid inputs are caught synchronously by trying to build
        // the request with bad channel/timestamp/emoji. We use tokio::test for
        // the async context but the validation happens before any HTTP.
        let rt = tokio::runtime::Runtime::new().unwrap();

        // Bad emoji should fail
        let result = rt.block_on(api.add_reaction("C123", "1234.5678", "bad emoji"));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("disallowed characters"));

        // Bad channel should fail
        let result = rt.block_on(api.add_reaction("bad channel!", "1234.5678", "thumbsup"));
        assert!(result.is_err());

        // Bad timestamp should fail
        let result = rt.block_on(api.add_reaction("C123", "not-a-ts", "thumbsup"));
        assert!(result.is_err());
    }
}
