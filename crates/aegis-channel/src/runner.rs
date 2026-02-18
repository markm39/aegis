//! Thread/runtime orchestration for the channel.
//!
//! Bridges the sync world (pilot event channel, alert events) with the async
//! Telegram API. Runs a single-threaded tokio runtime on a dedicated thread,
//! following the same pattern as the alert dispatcher.

use std::sync::mpsc::{Receiver, Sender};

use tracing::{info, warn};

use aegis_alert::AlertEvent;
use aegis_control::daemon::DaemonCommand;
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
    run_fleet(config, input_rx, None);
}

/// Run the channel with fleet-aware inbound command forwarding.
///
/// Like `run()`, but inbound Telegram commands are parsed as fleet commands
/// and forwarded as `DaemonCommand`s through the `feedback_tx` channel.
/// The daemon drains this channel alongside its control socket commands.
///
/// Call this from a dedicated `std::thread::spawn`.
pub fn run_fleet(
    config: ChannelConfig,
    input_rx: Receiver<ChannelInput>,
    feedback_tx: Option<Sender<DaemonCommand>>,
) {
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
                run_telegram(tg_config, input_rx, feedback_tx).await;
            }
        }
    });
}

async fn run_telegram(
    config: aegis_types::TelegramConfig,
    input_rx: Receiver<ChannelInput>,
    feedback_tx: Option<Sender<DaemonCommand>>,
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
                        handle_inbound_action(&channel, action, feedback_tx.as_ref()).await;
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

/// Handle an inbound action from Telegram.
///
/// If a `feedback_tx` is provided (fleet mode), attempts to parse the input
/// as a fleet command and forward it to the daemon. Falls back to legacy
/// single-agent command handling, and sends help text for unrecognized input.
async fn handle_inbound_action(
    channel: &impl crate::channel::Channel,
    action: InboundAction,
    feedback_tx: Option<&Sender<DaemonCommand>>,
) {
    match action {
        InboundAction::Command(ref cmd) => {
            // Legacy single-agent command -- log it
            info!(?cmd, "received inbound command from Telegram");

            // If in fleet mode, try to convert to a DaemonCommand
            // (single-agent commands don't have agent names, so they
            // can't be forwarded directly -- just log for now)
        }
        InboundAction::Unknown(ref text) => {
            if text.is_empty() {
                // /help command -- send help text
                let help = if feedback_tx.is_some() {
                    format::fleet_help_text()
                } else {
                    format::help_text()
                };
                let msg = crate::channel::OutboundMessage::text(help);
                if let Err(e) = channel.send(msg).await {
                    warn!("failed to send help text: {e}");
                }
                return;
            }

            // Try fleet command parsing if feedback channel is available
            if let Some(tx) = feedback_tx {
                if let Some(daemon_cmd) = format::parse_fleet_command(text) {
                    info!(?daemon_cmd, "forwarding fleet command from Telegram");
                    if tx.send(daemon_cmd).is_err() {
                        warn!("failed to forward fleet command (daemon feedback channel closed)");
                    }
                    return;
                }
            }

            info!(text, "unrecognized input from Telegram");
        }
    }
}
