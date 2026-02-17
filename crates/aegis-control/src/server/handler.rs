//! Transport-agnostic command handler.
//!
//! Processes [`Command`]s by forwarding them through the command channel
//! to the pilot supervisor and waiting for responses.

use tokio::sync::oneshot;

use crate::command::{Command, CommandResponse};
use crate::server::CommandTx;

/// Send a command to the pilot supervisor and wait for the response.
///
/// Returns `CommandResponse::error` if the supervisor is disconnected
/// or the response channel is dropped.
pub async fn handle_command(tx: &CommandTx, command: Command) -> CommandResponse {
    let (resp_tx, resp_rx) = oneshot::channel();

    if tx.send((command, resp_tx)).await.is_err() {
        return CommandResponse::error("pilot supervisor disconnected");
    }

    match resp_rx.await {
        Ok(response) => response,
        Err(_) => CommandResponse::error("response channel dropped"),
    }
}
