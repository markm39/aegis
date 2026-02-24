//! Thread/runtime orchestration for the channel.
//!
//! Bridges the sync world (pilot event channel, alert events) with the async
//! channel backends. Runs a single-threaded tokio runtime on a dedicated thread,
//! following the same pattern as the alert dispatcher.

use std::sync::mpsc::{Receiver, Sender};

use tracing::{info, warn};

use crate::auto_reply::HeartbeatConfig;
use crate::hooks::MessageHook;
use aegis_alert::AlertEvent;
use aegis_control::daemon::DaemonCommand;
use aegis_control::event::PilotWebhookEvent;
use aegis_types::ChannelConfig;

use crate::active_hours;
use crate::channel::{InboundAction, OutboundPhoto};
use crate::channel_routing::ChannelCommandRouter;
use crate::format;
use crate::slack;
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
    /// A plain text message to send (e.g., command response feedback).
    TextMessage(String),
    /// A photo message to send (e.g., snapshot).
    Photo(OutboundPhoto),
    /// Reload auto-reply rules (sent after add/remove/toggle operations).
    ReloadAutoReplies(Vec<crate::auto_reply::PersistentAutoReplyRule>),
}

/// Run the channel on the current thread with a single-threaded tokio runtime.
///
/// This function blocks until the `input_rx` channel is closed (sender dropped).
/// It processes outbound events from the pilot and alert systems, and polls for
/// inbound user commands. Inbound commands are currently logged but not forwarded
/// (command forwarding requires the supervisor to accept a `CommandRx`, which
/// will be wired in a follow-up).
///
/// Call this from a dedicated `std::thread::spawn`.
pub fn run(config: ChannelConfig, input_rx: Receiver<ChannelInput>) {
    run_fleet(config, input_rx, None, None, vec![]);
}

/// Run the channel with fleet-aware inbound command forwarding.
///
/// Like `run()`, but inbound commands are parsed as fleet commands and forwarded
/// as `DaemonCommand`s through the `feedback_tx` channel. The daemon drains this
/// channel alongside its control socket commands.
///
/// Call this from a dedicated `std::thread::spawn`.
pub fn run_fleet(
    config: ChannelConfig,
    input_rx: Receiver<ChannelInput>,
    feedback_tx: Option<Sender<DaemonCommand>>,
    router: Option<ChannelCommandRouter>,
    initial_auto_reply_rules: Vec<crate::auto_reply::PersistentAutoReplyRule>,
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
        let channel_type = config.channel_type_name();
        match config {
            ChannelConfig::Telegram(tg_config) => {
                run_telegram(tg_config, input_rx, feedback_tx, channel_type, router.as_ref(), initial_auto_reply_rules).await;
            }
            ChannelConfig::Slack(slack_config) => {
                run_slack(slack_config, input_rx, feedback_tx, channel_type, router.as_ref(), initial_auto_reply_rules).await;
            }
            ChannelConfig::Webhook(cfg) => {
                let channel = crate::webhook::WebhookChannel::new(crate::webhook::WebhookConfig {
                    name: cfg.name,
                    outbound_url: cfg.outbound_url,
                    inbound_url: cfg.inbound_url,
                    auth_header: cfg.auth_header,
                    payload_template: cfg.payload_template,
                });
                run_generic_channel(channel, cfg.active_hours, input_rx, feedback_tx, channel_type, router.as_ref(), initial_auto_reply_rules).await;
            }
            ChannelConfig::Discord(cfg) => {
                let channel = crate::discord::DiscordChannel::new(crate::discord::DiscordConfig {
                    webhook_url: cfg.webhook_url,
                    bot_token: cfg.bot_token,
                    channel_id: cfg.channel_id,
                    guild_id: cfg.guild_id,
                    application_id: cfg.application_id,
                    public_key: cfg.public_key,
                    authorized_user_ids: cfg.authorized_user_ids,
                    command_channel_id: cfg.command_channel_id,
                });
                run_generic_channel(channel, cfg.active_hours, input_rx, feedback_tx, channel_type, router.as_ref(), initial_auto_reply_rules).await;
            }
            ChannelConfig::Whatsapp(cfg) => {
                let channel =
                    crate::whatsapp::WhatsappChannel::new(crate::whatsapp::WhatsappConfig {
                        api_url: cfg.api_url,
                        access_token: cfg.access_token,
                        phone_number_id: cfg.phone_number_id,
                        app_secret: None,
                        verify_token: None,
                        webhook_port: None,
                        template_namespace: None,
                    });
                run_generic_channel(channel, cfg.active_hours, input_rx, feedback_tx, channel_type, router.as_ref(), initial_auto_reply_rules).await;
            }
            ChannelConfig::Signal(cfg) => {
                let channel = match crate::signal::SignalChannel::new(crate::signal::SignalConfig {
                    api_url: cfg.api_url,
                    phone_number: cfg.phone_number,
                    recipients: cfg.recipients,
                    poll_interval_secs: 5,
                    group_ids: Vec::new(),
                    trust_mode: "trust_all".to_string(),
                }) {
                    Ok(ch) => ch,
                    Err(e) => {
                        tracing::error!("failed to create Signal channel: {e}");
                        return;
                    }
                };
                run_generic_channel(channel, cfg.active_hours, input_rx, feedback_tx, channel_type, router.as_ref(), initial_auto_reply_rules).await;
            }
            ChannelConfig::Matrix(cfg) => {
                let channel = crate::matrix::MatrixChannel::new(crate::matrix::MatrixConfig {
                    homeserver_url: cfg.homeserver_url,
                    access_token: cfg.access_token,
                    room_id: cfg.room_id,
                });
                run_generic_channel(channel, cfg.active_hours, input_rx, feedback_tx, channel_type, router.as_ref(), initial_auto_reply_rules).await;
            }
            ChannelConfig::Imessage(cfg) => {
                let channel =
                    match crate::imessage::ImessageChannel::new(crate::imessage::ImessageConfig {
                        recipient: cfg.recipient,
                        mode: Default::default(),
                        bluebubbles_url: None,
                        bluebubbles_password: None,
                        poll_interval_secs: 10,
                        chat_db_path: None,
                    }) {
                        Ok(ch) => ch,
                        Err(e) => {
                            tracing::error!("failed to create iMessage channel: {e}");
                            return;
                        }
                    };
                run_generic_channel(channel, cfg.active_hours, input_rx, feedback_tx, channel_type, router.as_ref(), initial_auto_reply_rules).await;
            }
            ChannelConfig::Irc(cfg) => {
                let channel = crate::irc::IrcChannel::new(crate::irc::IrcConfig {
                    server: cfg.server,
                    channel: cfg.channel,
                    nick: cfg.nick,
                });
                run_generic_channel(channel, cfg.active_hours, input_rx, feedback_tx, channel_type, router.as_ref(), initial_auto_reply_rules).await;
            }
            ChannelConfig::Msteams(cfg) => {
                let channel = crate::msteams::MsteamsChannel::new(crate::msteams::MsteamsConfig {
                    webhook_url: cfg.webhook_url,
                });
                run_generic_channel(channel, cfg.active_hours, input_rx, feedback_tx, channel_type, router.as_ref(), initial_auto_reply_rules).await;
            }
            ChannelConfig::Googlechat(cfg) => {
                let channel = crate::googlechat::GooglechatChannel::new(
                    crate::googlechat::GooglechatConfig {
                        webhook_url: cfg.webhook_url,
                    },
                );
                run_generic_channel(channel, cfg.active_hours, input_rx, feedback_tx, channel_type, router.as_ref(), initial_auto_reply_rules).await;
            }
            ChannelConfig::Feishu(cfg) => {
                let channel = crate::feishu::FeishuChannel::new(crate::feishu::FeishuConfig {
                    webhook_url: cfg.webhook_url,
                    secret: cfg.secret,
                });
                run_generic_channel(channel, cfg.active_hours, input_rx, feedback_tx, channel_type, router.as_ref(), initial_auto_reply_rules).await;
            }
            ChannelConfig::Line(cfg) => {
                let channel = crate::line::LineChannel::new(crate::line::LineConfig {
                    channel_access_token: cfg.channel_access_token,
                    user_id: cfg.user_id,
                    channel_secret: None,
                    webhook_port: None,
                    oauth_channel_id: None,
                    multicast_enabled: false,
                });
                run_generic_channel(channel, cfg.active_hours, input_rx, feedback_tx, channel_type, router.as_ref(), initial_auto_reply_rules).await;
            }
            ChannelConfig::Nostr(cfg) => {
                let channel = crate::nostr::NostrChannel::new(crate::nostr::NostrConfig {
                    relay_url: cfg.relay_url,
                    private_key_hex: cfg.private_key_hex,
                });
                run_generic_channel(channel, cfg.active_hours, input_rx, feedback_tx, channel_type, router.as_ref(), initial_auto_reply_rules).await;
            }
            ChannelConfig::Mattermost(cfg) => {
                let channel = crate::mattermost::MattermostChannel::new(
                    crate::mattermost::MattermostConfig {
                        webhook_url: cfg.webhook_url,
                        channel_id: cfg.channel_id,
                    },
                );
                run_generic_channel(channel, cfg.active_hours, input_rx, feedback_tx, channel_type, router.as_ref(), initial_auto_reply_rules).await;
            }
            ChannelConfig::VoiceCall(cfg) => {
                let channel =
                    crate::voice_call::VoiceCallChannel::new(crate::voice_call::VoiceCallConfig {
                        api_url: cfg.api_url,
                        from_number: cfg.from_number,
                        to_number: cfg.to_number,
                    });
                run_generic_channel(channel, cfg.active_hours, input_rx, feedback_tx, channel_type, router.as_ref(), initial_auto_reply_rules).await;
            }
            ChannelConfig::Twitch(cfg) => {
                let channel = match crate::twitch::TwitchChannel::new(crate::twitch::TwitchConfig {
                    oauth_token: cfg.oauth_token,
                    channel_name: cfg.channel_name,
                    bot_username: cfg.bot_username,
                }) {
                    Ok(ch) => ch,
                    Err(e) => {
                        tracing::error!("failed to create Twitch channel: {e}");
                        return;
                    }
                };
                run_generic_channel(channel, cfg.active_hours, input_rx, feedback_tx, channel_type, router.as_ref(), initial_auto_reply_rules).await;
            }
            ChannelConfig::Nextcloud(cfg) => {
                let channel = match crate::nextcloud::NextcloudChannel::new(
                    crate::nextcloud::NextcloudConfig {
                        server_url: cfg.server_url,
                        username: cfg.username,
                        app_password: cfg.app_password,
                        room_token: cfg.room_token,
                    },
                ) {
                    Ok(ch) => ch,
                    Err(e) => {
                        tracing::error!("failed to create Nextcloud Talk channel: {e}");
                        return;
                    }
                };
                run_generic_channel(channel, cfg.active_hours, input_rx, feedback_tx, channel_type, router.as_ref(), initial_auto_reply_rules).await;
            }
            ChannelConfig::Zalo(cfg) => {
                let channel = match crate::zalo::ZaloChannel::new(crate::zalo::ZaloConfig {
                    oa_id: cfg.oa_id,
                    access_token: cfg.access_token,
                    secret_key: cfg.secret_key,
                }) {
                    Ok(ch) => ch,
                    Err(e) => {
                        tracing::error!("failed to create Zalo channel: {e}");
                        return;
                    }
                };
                run_generic_channel(channel, cfg.active_hours, input_rx, feedback_tx, channel_type, router.as_ref(), initial_auto_reply_rules).await;
            }
            ChannelConfig::Tlon(cfg) => {
                let channel = match crate::tlon::TlonChannel::new(crate::tlon::TlonConfig {
                    ship_url: cfg.ship_url,
                    ship_name: cfg.ship_name,
                }) {
                    Ok(ch) => ch,
                    Err(e) => {
                        tracing::error!("failed to create Tlon channel: {e}");
                        return;
                    }
                };
                run_generic_channel(channel, cfg.active_hours, input_rx, feedback_tx, channel_type, router.as_ref(), initial_auto_reply_rules).await;
            }
            ChannelConfig::Lobster(cfg) => {
                let channel =
                    match crate::lobster::LobsterChannel::new(crate::lobster::LobsterConfig {
                        api_url: cfg.api_url,
                        api_key: cfg.api_key,
                    }) {
                        Ok(ch) => ch,
                        Err(e) => {
                            tracing::error!("failed to create Lobster channel: {e}");
                            return;
                        }
                    };
                run_generic_channel(channel, cfg.active_hours, input_rx, feedback_tx, channel_type, router.as_ref(), initial_auto_reply_rules).await;
            }
            ChannelConfig::Gmail(_cfg) => {
                // Gmail channel trait implementation is not yet available (task 2).
                // Log a warning and return without running.
                tracing::warn!("Gmail channel is not yet fully implemented; skipping");
            }
        }
    });
}

/// Generic channel runner for webhook-based backends.
///
/// Runs the same send/recv loop pattern as Telegram and Slack, but works
/// with any `Channel` implementation. Used by all webhook-based channel stubs.
async fn run_generic_channel(
    mut channel: impl crate::channel::Channel + std::marker::Sync,
    active_hours_cfg: Option<aegis_types::ActiveHoursConfig>,
    input_rx: Receiver<ChannelInput>,
    feedback_tx: Option<Sender<DaemonCommand>>,
    channel_type: &str,
    router: Option<&ChannelCommandRouter>,
    initial_auto_reply_rules: Vec<crate::auto_reply::PersistentAutoReplyRule>,
) {
    use crate::auto_reply::PersistentAutoReplyEngine;

    let channel_name = channel.name().to_string();
    let has_typing = channel.capabilities().typing_indicators;
    let rule_count = initial_auto_reply_rules.len();
    info!(channel = %channel_name, rules = rule_count, "channel starting with auto-reply rules");

    let (bridge_tx, mut bridge_rx) = tokio::sync::mpsc::channel::<ChannelInput>(64);
    tokio::task::spawn_blocking(move || {
        while let Ok(input) = input_rx.recv() {
            if bridge_tx.blocking_send(input).is_err() {
                break;
            }
        }
    });

    let mut auto_reply = PersistentAutoReplyEngine::new(initial_auto_reply_rules);
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
                    ChannelInput::TextMessage(ref text) => {
                        crate::channel::OutboundMessage::text(text)
                    }
                    ChannelInput::Photo(_) => {
                        warn!(channel = %channel_name, "photo messages not supported");
                        continue;
                    }
                    ChannelInput::ReloadAutoReplies(rules) => {
                        let count = rules.len();
                        auto_reply = PersistentAutoReplyEngine::new(rules);
                        info!(channel = %channel_name, rules = count, "auto-reply rules reloaded");
                        continue;
                    }
                };

                if !active_hours::within_active_hours(
                    active_hours_cfg.as_ref(),
                    chrono::Utc::now(),
                ) {
                    warn!("outbound message suppressed (inactive hours)");
                    continue;
                }

                {
                    // Send typing indicator before the message for visual feedback
                    if has_typing {
                        if let Err(e) = channel.send_typing().await {
                            tracing::debug!("typing indicator failed (non-fatal): {e}");
                        }
                    }

                    let text_copy = message.text.clone();
                    tracing::debug!(hook = ?MessageHook::pre_send(channel.name(), &text_copy), "message hook");
                    let send_result = channel.send(message).await;
                    let success = send_result.is_ok();
                    tracing::debug!(hook = ?MessageHook::post_send(channel.name(), &text_copy, success), "message hook");
                    if let Err(e) = send_result {
                        warn!("failed to send outbound message: {e}");
                    }
                }
            }
            _ = interval.tick() => {
                match channel.recv().await {
                    Ok(Some(action)) => {
                        tracing::debug!(hook = ?MessageHook::received(channel.name(), &format!("{:?}", action)), "message hook");

                        // Check auto-reply before fleet command parsing
                        if let InboundAction::Unknown(ref text) = action {
                            if let Some(reply) = auto_reply.check(text, None) {
                                let msg = crate::channel::OutboundMessage::text(reply);
                                if let Err(e) = channel.send(msg).await {
                                    warn!("failed to send auto-reply: {e}");
                                }
                                continue;
                            }
                        }

                        handle_inbound_action(&channel, action, feedback_tx.as_ref(), channel_type, router).await;
                    }
                    Ok(None) => {}
                    Err(crate::channel::ChannelError::Shutdown) => {
                        info!(channel = %channel_name, "channel shut down");
                        break;
                    }
                    Err(e) => {
                        warn!(channel = %channel_name, "channel recv error: {e}");
                    }
                }
            }
            else => break,
        }
    }

    info!(channel = %channel_name, "channel stopped");
}

async fn run_slack(
    config: aegis_types::SlackConfig,
    input_rx: Receiver<ChannelInput>,
    feedback_tx: Option<Sender<DaemonCommand>>,
    channel_type: &str,
    router: Option<&ChannelCommandRouter>,
    initial_auto_reply_rules: Vec<crate::auto_reply::PersistentAutoReplyRule>,
) {
    use crate::auto_reply::PersistentAutoReplyEngine;
    use crate::channel::Channel;

    let mut channel = slack::SlackChannel::new(config.clone());
    let has_typing = channel.capabilities().typing_indicators;

    let rule_count = initial_auto_reply_rules.len();
    info!(rules = rule_count, "Slack channel starting with auto-reply rules");

    let (bridge_tx, mut bridge_rx) = tokio::sync::mpsc::channel::<ChannelInput>(64);
    tokio::task::spawn_blocking(move || {
        while let Ok(input) = input_rx.recv() {
            if bridge_tx.blocking_send(input).is_err() {
                break;
            }
        }
    });

    let mut auto_reply = PersistentAutoReplyEngine::new(initial_auto_reply_rules);
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
                    ChannelInput::TextMessage(ref text) => {
                        crate::channel::OutboundMessage::text(text)
                    }
                    ChannelInput::Photo(_) => {
                        warn!("slack channel does not support photos");
                        continue;
                    }
                    ChannelInput::ReloadAutoReplies(rules) => {
                        let count = rules.len();
                        auto_reply = PersistentAutoReplyEngine::new(rules);
                        info!(rules = count, "auto-reply rules reloaded");
                        continue;
                    }
                };

                if !active_hours::within_active_hours(
                    config.active_hours.as_ref(),
                    chrono::Utc::now(),
                ) {
                    warn!("outbound message suppressed (inactive hours)");
                    continue;
                }

                {
                    // Send typing indicator before the message for visual feedback
                    if has_typing {
                        if let Err(e) = channel.send_typing().await {
                            tracing::debug!("typing indicator failed (non-fatal): {e}");
                        }
                    }

                    let text_copy = message.text.clone();
                    tracing::debug!(hook = ?MessageHook::pre_send(channel.name(), &text_copy), "message hook");
                    let send_result = channel.send(message).await;
                    let success = send_result.is_ok();
                    tracing::debug!(hook = ?MessageHook::post_send(channel.name(), &text_copy, success), "message hook");
                    if let Err(e) = send_result {
                        warn!("failed to send outbound message: {e}");
                    }
                }
            }
            _ = interval.tick() => {
                match channel.recv().await {
                    Ok(Some(action)) => {
                        tracing::debug!(hook = ?MessageHook::received(channel.name(), &format!("{:?}", action)), "message hook");

                        // Check auto-reply before fleet command parsing
                        if let InboundAction::Unknown(ref text) = action {
                            if let Some(reply) = auto_reply.check(text, None) {
                                let msg = crate::channel::OutboundMessage::text(reply);
                                if let Err(e) = channel.send(msg).await {
                                    warn!("failed to send auto-reply: {e}");
                                }
                                continue;
                            }
                        }

                        handle_inbound_action(&channel, action, feedback_tx.as_ref(), channel_type, router).await;
                    }
                    Ok(None) => {}
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

    info!("Slack channel stopped");
}

async fn run_telegram(
    config: aegis_types::TelegramConfig,
    input_rx: Receiver<ChannelInput>,
    feedback_tx: Option<Sender<DaemonCommand>>,
    channel_type: &str,
    router: Option<&ChannelCommandRouter>,
    initial_auto_reply_rules: Vec<crate::auto_reply::PersistentAutoReplyRule>,
) {
    use crate::auto_reply::PersistentAutoReplyEngine;
    use crate::channel::Channel;

    let mut channel = telegram::TelegramChannel::new(config.clone());
    let has_typing = channel.capabilities().typing_indicators;

    // Send startup announcement
    let rule_count = initial_auto_reply_rules.len();
    info!(rules = rule_count, "Telegram channel starting with auto-reply rules");

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

    let mut auto_reply = PersistentAutoReplyEngine::new(initial_auto_reply_rules);

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
                    ChannelInput::TextMessage(ref text) => {
                        crate::channel::OutboundMessage::text(format::escape_md(text))
                    }
                    ChannelInput::Photo(ref photo) => {
                        if !active_hours::within_active_hours(
                            config.active_hours.as_ref(),
                            chrono::Utc::now(),
                        ) {
                            warn!("outbound photo suppressed (inactive hours)");
                            continue;
                        }
                        if let Err(e) = channel.send_photo(photo.clone()).await {
                            warn!("failed to send photo: {e}");
                        }
                        continue;
                    }
                    ChannelInput::ReloadAutoReplies(rules) => {
                        let count = rules.len();
                        auto_reply = PersistentAutoReplyEngine::new(rules);
                        info!(rules = count, "auto-reply rules reloaded");
                        continue;
                    }
                };

                if !active_hours::within_active_hours(
                    config.active_hours.as_ref(),
                    chrono::Utc::now(),
                ) {
                    warn!("outbound message suppressed (inactive hours)");
                    continue;
                }
                {
                    // Send typing indicator before the message for visual feedback
                    if has_typing {
                        if let Err(e) = channel.send_typing().await {
                            tracing::debug!("typing indicator failed (non-fatal): {e}");
                        }
                    }

                    let text_copy = message.text.clone();
                    tracing::debug!(hook = ?MessageHook::pre_send(channel.name(), &text_copy), "message hook");
                    let send_result = channel.send(message).await;
                    let success = send_result.is_ok();
                    tracing::debug!(hook = ?MessageHook::post_send(channel.name(), &text_copy, success), "message hook");
                    if let Err(e) = send_result {
                        warn!("failed to send outbound message: {e}");
                    }
                }
            }

            _ = interval.tick() => {
                // Poll for inbound actions
                match channel.recv().await {
                    Ok(Some(action)) => {
                        tracing::debug!(hook = ?MessageHook::received(channel.name(), &format!("{:?}", action)), "message hook");

                        // Check auto-reply before fleet command parsing
                        if let InboundAction::Unknown(ref text) = action {
                            if let Some(reply) = auto_reply.check(text, None) {
                                let msg = crate::channel::OutboundMessage::text(reply);
                                if let Err(e) = channel.send(msg).await {
                                    warn!("failed to send auto-reply: {e}");
                                }
                                continue;
                            }
                        }

                        handle_inbound_action(&channel, action, feedback_tx.as_ref(), channel_type, router).await;
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

/// Format a heartbeat message from the heartbeat config.
///
/// Since fleet data is not directly available in the channel layer,
/// placeholder values are used.
fn _format_heartbeat(config: &HeartbeatConfig) -> String {
    config.format_message("N/A", "N/A", "N/A")
}

/// Handle an inbound action from a channel.
///
/// If a `feedback_tx` is provided (fleet mode), attempts to parse the input
/// as a fleet command and forward it to the daemon. Falls back to legacy
/// single-agent command handling, and sends help text for unrecognized input.
async fn handle_inbound_action(
    channel: &impl crate::channel::Channel,
    action: InboundAction,
    feedback_tx: Option<&Sender<DaemonCommand>>,
    channel_type: &str,
    router: Option<&ChannelCommandRouter>,
) {
    match action {
        InboundAction::Command(ref cmd) => {
            // Legacy single-agent command -- log it
            info!(?cmd, "received inbound command");

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

            // Apply channel routing restrictions before parsing
            if let Some(router) = router {
                if let Err(e) = router.resolve_command(channel_type, text) {
                    info!(channel = channel_type, error = %e, "command denied by channel routing");
                    let msg = crate::channel::OutboundMessage::text(format!("Command denied: {e}"));
                    if let Err(send_err) = channel.send(msg).await {
                        warn!("failed to send routing denial: {send_err}");
                    }
                    return;
                }
            }

            // Try fleet command parsing if feedback channel is available
            if let Some(tx) = feedback_tx {
                if let Some(daemon_cmd) = format::parse_fleet_command(text) {
                    info!(?daemon_cmd, "forwarding fleet command");
                    if tx.send(daemon_cmd).is_err() {
                        warn!("failed to forward fleet command (daemon feedback channel closed)");
                    }
                    return;
                }
            }

            info!(text, "unrecognized input from channel");
        }
    }
}
