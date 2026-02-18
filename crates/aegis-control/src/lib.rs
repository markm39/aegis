//! Bidirectional control plane for the Aegis pilot supervisor.
//!
//! Provides remote monitoring and command execution via:
//! - Unix domain socket (always available, filesystem-secured)
//! - Optional HTTP/REST server (for remote access with API key auth)
//!
//! The control plane allows users to:
//! - Check pilot status and recent agent output
//! - Approve or deny pending permission requests
//! - Send input/nudges to the agent
//! - Hot-reload Cedar policies

pub mod command;
pub mod daemon;
pub mod event;
pub mod hooks;
pub mod pending;
pub mod server;
