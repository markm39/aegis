//! Long-polling loop for Telegram Bot API `getUpdates`.
//!
//! Filters incoming updates by `chat_id`, parses text commands and
//! callback queries, and forwards [`InboundAction`]s through a channel.

use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::channel::InboundAction;
use crate::format;

use super::api::TelegramApi;

/// Run the long-polling loop until the cancellation token fires.
///
/// Parsed actions are sent through `action_tx`. The poller handles:
/// - Text messages: parsed via [`format::parse_text_command`]
/// - Callback queries: parsed via [`format::parse_callback`], with button
///   cleanup and callback acknowledgement
/// - Unknown commands: help text sent back directly
pub async fn poll_loop(
    api: Arc<TelegramApi>,
    chat_id: i64,
    poll_timeout: u64,
    action_tx: mpsc::Sender<InboundAction>,
    mut cancel: tokio::sync::watch::Receiver<bool>,
) {
    let mut offset: Option<i64> = None;
    let mut backoff_secs = 1u64;

    info!(chat_id, "Telegram poller started");

    loop {
        // Check for shutdown
        if *cancel.borrow() {
            info!("Telegram poller shutting down");
            return;
        }

        let updates = tokio::select! {
            result = api.get_updates(offset, poll_timeout) => result,
            _ = cancel.changed() => {
                info!("Telegram poller cancelled");
                return;
            }
        };

        match updates {
            Ok(updates) => {
                backoff_secs = 1; // Reset backoff on success

                for update in updates {
                    // Advance offset to acknowledge this update
                    offset = Some(update.update_id + 1);

                    // Handle text messages
                    if let Some(msg) = update.message {
                        if msg.chat.id != chat_id {
                            debug!(
                                from_chat = msg.chat.id,
                                expected = chat_id,
                                "ignoring message from unauthorized chat"
                            );
                            continue;
                        }

                        if let Some(text) = msg.text {
                            let action = format::parse_text_command(&text);

                            match &action {
                                InboundAction::Unknown(s) => {
                                    // Send help text back
                                    let help = if s.is_empty() {
                                        format::help_text()
                                    } else {
                                        format!(
                                            "Unknown command: `{}`\n\n{}",
                                            format::escape_md(s),
                                            format::help_text()
                                        )
                                    };
                                    let _ = api
                                        .send_message(chat_id, &help, Some("MarkdownV2"), None, false)
                                        .await;
                                }
                                InboundAction::Command(_) => {
                                    if action_tx.send(action).await.is_err() {
                                        warn!("action channel closed, stopping poller");
                                        return;
                                    }
                                }
                            }
                        }
                    }

                    // Handle callback queries (inline keyboard button presses)
                    if let Some(cb) = update.callback_query {
                        // Verify chat_id from the callback's message
                        let cb_chat_id = cb.message.as_ref().map(|m| m.chat.id);
                        if cb_chat_id != Some(chat_id) {
                            debug!("ignoring callback from unauthorized chat");
                            // Still ack to remove spinner
                            let _ = api.answer_callback_query(&cb.id, None).await;
                            continue;
                        }

                        if let Some(data) = &cb.data {
                            if let Some(action) = format::parse_callback(data) {
                                // Ack the callback (dismiss spinner)
                                let ack_text = if data.starts_with("approve:") {
                                    "Approved"
                                } else {
                                    "Denied"
                                };
                                let _ = api
                                    .answer_callback_query(&cb.id, Some(ack_text))
                                    .await;

                                // Remove buttons to prevent double-tap
                                if let Some(msg) = &cb.message {
                                    let _ = api
                                        .remove_reply_markup(msg.chat.id, msg.message_id)
                                        .await;
                                }

                                if action_tx.send(action).await.is_err() {
                                    warn!("action channel closed, stopping poller");
                                    return;
                                }
                            } else {
                                let _ = api
                                    .answer_callback_query(&cb.id, Some("Invalid action"))
                                    .await;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, backoff_secs, "getUpdates failed, backing off");
                tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(60);
            }
        }
    }
}
