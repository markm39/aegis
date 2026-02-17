//! Control plane server implementations.
//!
//! - [`handler`]: transport-agnostic command handler
//! - [`http`]: axum-based HTTP REST server
//! - [`unix`]: Unix domain socket server (NDJSON protocol)

pub mod handler;
pub mod http;
pub mod unix;

use std::path::PathBuf;

use tokio::sync::mpsc;

use crate::command::{Command, CommandResponse};

/// A channel pair for sending commands and receiving responses.
///
/// The control server holds the sender; the pilot supervisor holds the receiver.
/// Each command includes a oneshot channel for its response.
pub type CommandTx = mpsc::Sender<(Command, tokio::sync::oneshot::Sender<CommandResponse>)>;
pub type CommandRx = mpsc::Receiver<(Command, tokio::sync::oneshot::Sender<CommandResponse>)>;

/// Create a new command channel pair.
pub fn command_channel(buffer: usize) -> (CommandTx, CommandRx) {
    mpsc::channel(buffer)
}

/// Configuration for the control server.
#[derive(Debug, Clone)]
pub struct ControlServerConfig {
    /// Path for the Unix domain socket.
    pub socket_path: PathBuf,
    /// HTTP listen address (empty = disabled).
    pub http_listen: String,
    /// API key for HTTP authentication (empty = no auth).
    pub api_key: String,
}

impl ControlServerConfig {
    /// Default socket path for a given session ID.
    pub fn default_socket_path(session_id: &uuid::Uuid) -> PathBuf {
        let aegis_dir = dirs_or_default();
        aegis_dir.join("pilot").join(format!("{session_id}.sock"))
    }
}

/// Get the ~/.aegis directory, creating it if needed.
fn dirs_or_default() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".aegis")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_channel_works() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (tx, mut rx) = command_channel(16);
            let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();

            tx.send((Command::Status, resp_tx)).await.unwrap();

            let (cmd, responder) = rx.recv().await.unwrap();
            assert!(matches!(cmd, Command::Status));
            responder.send(CommandResponse::ok("running")).unwrap();

            let resp = resp_rx.await.unwrap();
            assert!(resp.ok);
        });
    }
}
