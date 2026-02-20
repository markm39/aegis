//! Minimal Slack Web API wrapper for outbound messages and streaming.

use reqwest::Client;
use serde::Deserialize;

use crate::channel::ChannelError;

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
}
