//! Bidirectional messaging channel for remote agent control.
//!
//! Receives pilot events and alert events (outbound) and forwards user
//! commands back to the supervisor (inbound). Currently supports Telegram
//! via the Bot API; additional backends can be added by implementing the
//! [`Channel`] trait.
//!
//! # Architecture
//!
//! - [`channel`]: core trait and types for bidirectional messaging
//! - [`format`]: message formatting (outbound) and command parsing (inbound)
//! - [`telegram`]: Telegram Bot API implementation
//! - [`runner`]: thread/runtime orchestration bridging sync and async worlds

pub mod channel;
pub mod format;
pub mod runner;
pub mod telegram;

pub use channel::{Channel, ChannelError, InboundAction, OutboundMessage};
pub use runner::{run, run_fleet, ChannelInput};
