//! Bidirectional messaging channel for remote agent control.
//!
//! Receives pilot events and alert events (outbound) and forwards user
//! commands back to the supervisor (inbound). Supports Telegram, Slack,
//! Discord, and many more backends via the [`Channel`] trait.
//!
//! # Architecture
//!
//! - [`channel`]: core trait and types for bidirectional messaging
//! - [`format`]: message formatting (outbound) and command parsing (inbound)
//! - [`telegram`]: Telegram Bot API implementation (full bidirectional)
//! - [`slack`]: Slack Web API implementation (outbound + inbound polling)
//! - [`webhook`]: generic webhook adapter for simple HTTP POST channels
//! - [`auto_reply`]: auto-reply rules engine for inbound messages
//! - [`runner`]: thread/runtime orchestration bridging sync and async worlds

pub mod access_control;
pub mod active_hours;
pub mod auto_reply;
pub mod broadcast_group;
pub mod channel;
pub mod channel_routing;
pub mod discord;
pub mod feishu;
pub mod format;
pub mod gmail;
pub mod googlechat;
pub mod hooks;
pub mod imessage;
pub mod irc;
pub mod line;
pub mod lobster;
pub mod matrix;
pub mod mattermost;
pub mod media_pipeline;
pub mod msteams;
pub mod multi_account;
pub mod nextcloud;
pub mod nostr;
pub mod polls;
pub mod presence;
pub mod runner;
pub mod signal;
pub mod slack;
pub mod telegram;
pub mod tlon;
pub mod twitch;
pub mod unified;
pub mod voice_call;
pub mod voice_channel;
pub mod webchat;
pub mod webhook;
pub mod whatsapp;
pub mod zalo;

pub use channel::{
    Channel, ChannelCapabilities, ChannelError, InboundAction, MediaPayload, OutboundMessage,
};
pub use runner::{run, run_fleet, ChannelInput};
