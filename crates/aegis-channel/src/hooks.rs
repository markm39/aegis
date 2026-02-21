//! Message lifecycle hook events for audit and observability.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Message lifecycle events emitted by the channel layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageHook {
    /// Emitted before a message is sent through the channel.
    PreSend {
        channel_name: String,
        message_preview: String,
        timestamp: DateTime<Utc>,
    },
    /// Emitted after a message is successfully sent.
    PostSend {
        channel_name: String,
        message_preview: String,
        success: bool,
        timestamp: DateTime<Utc>,
    },
    /// Emitted when an inbound message is received from the channel.
    Received {
        channel_name: String,
        content_preview: String,
        timestamp: DateTime<Utc>,
    },
}

impl MessageHook {
    /// Create a PreSend event with a truncated preview (max 200 chars).
    pub fn pre_send(channel_name: &str, message: &str) -> Self {
        let preview = truncate_preview(message, 200);
        Self::PreSend {
            channel_name: channel_name.to_string(),
            message_preview: preview,
            timestamp: Utc::now(),
        }
    }

    /// Create a PostSend event.
    pub fn post_send(channel_name: &str, message: &str, success: bool) -> Self {
        let preview = truncate_preview(message, 200);
        Self::PostSend {
            channel_name: channel_name.to_string(),
            message_preview: preview,
            success,
            timestamp: Utc::now(),
        }
    }

    /// Create a Received event.
    pub fn received(channel_name: &str, content: &str) -> Self {
        let preview = truncate_preview(content, 200);
        Self::Received {
            channel_name: channel_name.to_string(),
            content_preview: preview,
            timestamp: Utc::now(),
        }
    }
}

fn truncate_preview(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        let mut end = max_len;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &s[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pre_send_truncates_long_messages() {
        let long_msg = "a".repeat(300);
        let hook = MessageHook::pre_send("telegram", &long_msg);
        match hook {
            MessageHook::PreSend {
                message_preview, ..
            } => {
                assert!(message_preview.len() <= 203); // 200 + "..."
                assert!(message_preview.ends_with("..."));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn short_message_not_truncated() {
        let hook = MessageHook::pre_send("slack", "hello");
        match hook {
            MessageHook::PreSend {
                message_preview, ..
            } => {
                assert_eq!(message_preview, "hello");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn post_send_captures_success() {
        let hook = MessageHook::post_send("telegram", "test", true);
        match hook {
            MessageHook::PostSend { success, .. } => assert!(success),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn received_event_created() {
        let hook = MessageHook::received("slack", "user input");
        match hook {
            MessageHook::Received {
                content_preview,
                channel_name,
                ..
            } => {
                assert_eq!(content_preview, "user input");
                assert_eq!(channel_name, "slack");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn serialization_roundtrip() {
        let hook = MessageHook::pre_send("test", "hello world");
        let json = serde_json::to_string(&hook).unwrap();
        let back: MessageHook = serde_json::from_str(&json).unwrap();
        match (hook, back) {
            (
                MessageHook::PreSend {
                    message_preview: a, ..
                },
                MessageHook::PreSend {
                    message_preview: b, ..
                },
            ) => {
                assert_eq!(a, b);
            }
            _ => panic!("roundtrip failed"),
        }
    }
}
