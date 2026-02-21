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

pub mod active_hours;
pub mod auto_reply;
pub mod channel;
pub mod discord;
pub mod feishu;
pub mod format;
pub mod googlechat;
pub mod hooks;
pub mod imessage;
pub mod irc;
pub mod line;
pub mod matrix;
pub mod mattermost;
pub mod msteams;
pub mod nostr;
pub mod runner;
pub mod signal;
pub mod slack;
pub mod telegram;
pub mod voice_call;
pub mod webhook;
pub mod whatsapp;

pub use channel::{Channel, ChannelError, InboundAction, OutboundMessage};
pub use runner::{run, run_fleet, ChannelInput};
