//! Thread/runtime orchestration for the channel.
//!
//! Bridges the sync world (pilot event channel, alert events) with the async
//! Telegram API. Runs a single-threaded tokio runtime on a dedicated thread,
//! following the same pattern as the alert dispatcher.

use std::sync::mpsc::Receiver;

use tracing::{info, warn};

use aegis_alert::AlertEvent;
use aegis_control::event::PilotWebhookEvent;
use aegis_types::ChannelConfig;

use crate::channel::InboundAction;
use crate::format;
use crate::telegram;

/// Input events fed to the channel runner from the pilot/alert system.
#[derive(Debug)]
pub enum ChannelInput {
    /// An alert event with the rule name that triggered it.
    Alert {
        event: AlertEvent,
        rule_name: String,
    },
    /// A pilot webhook event (permission decisions, stalls, exits, etc.).
    PilotEvent(PilotWebhookEvent),
}

/// Run the channel on the current thread with a single-threaded tokio runtime.
///
/// This function blocks until the `input_rx` channel is closed (sender dropped).
/// It processes outbound events from the pilot and alert systems, and polls for
/// inbound user commands from Telegram. Inbound commands are currently logged
/// but not forwarded (command forwarding requires the supervisor to accept a
/// `CommandRx`, which will be wired in a follow-up).
///
/// Call this from a dedicated `std::thread::spawn`.
pub fn run(config: ChannelConfig, input_rx: Receiver<ChannelInput>) {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            warn!("failed to create channel runtime: {e}");
            return;
        }
    };

    rt.block_on(async move {
        match config {
            ChannelConfig::Telegram(tg_config) => {
                run_telegram(tg_config, input_rx).await;
            }
        }
    });
}

async fn run_telegram(
    config: aegis_types::TelegramConfig,
    input_rx: Receiver<ChannelInput>,
) {
    use crate::channel::Channel;

    let mut channel = telegram::TelegramChannel::new(config.clone());

    // Send startup announcement
    info!("Telegram channel starting");

    // Bridge the sync mpsc::Receiver to async. We use a small bridge task
    // that reads from the std channel and forwards to a tokio channel.
    let (bridge_tx, mut bridge_rx) = tokio::sync::mpsc::channel::<ChannelInput>(64);

    // Spawn a blocking task for the bridge
    tokio::task::spawn_blocking(move || {
        while let Ok(input) = input_rx.recv() {
            if bridge_tx.blocking_send(input).is_err() {
                break;
            }
        }
    });

    // Main loop: process outbound events and poll for inbound actions
    let mut interval = tokio::time::interval(std::time::Duration::from_millis(200));

    loop {
        tokio::select! {
            Some(input) = bridge_rx.recv() => {
                let message = match input {
                    ChannelInput::Alert { ref event, ref rule_name } => {
                        format::format_alert(event, rule_name)
                    }
                    ChannelInput::PilotEvent(ref event) => {
                        format::format_pilot_event(event)
                    }
                };

                if let Err(e) = channel.send(message).await {
                    warn!("failed to send outbound message: {e}");
                }
            }

            _ = interval.tick() => {
                // Poll for inbound actions
                match channel.recv().await {
                    Ok(Some(action)) => {
                        handle_inbound_action(action);
                    }
                    Ok(None) => {} // No pending action
                    Err(crate::channel::ChannelError::Shutdown) => {
                        info!("channel shut down");
                        break;
                    }
                    Err(e) => {
                        warn!("channel recv error: {e}");
                    }
                }
            }

            else => break,
        }
    }

    info!("Telegram channel stopped");
}

fn handle_inbound_action(action: InboundAction) {
    // For now, log the action. Full integration requires wiring CommandTx
    // into the supervisor, which the daemon agent is working on.
    match action {
        InboundAction::Command(cmd) => {
            info!(?cmd, "received inbound command from Telegram (not yet forwarded)");
        }
        InboundAction::Unknown(text) => {
            info!(text, "received unknown input from Telegram");
        }
    }
}
