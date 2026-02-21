//! Unix domain socket server for local pilot control.
//!
//! Uses newline-delimited JSON (NDJSON) over a Unix socket for fast,
//! filesystem-secured local communication. The socket path defaults to
//! `~/.aegis/pilot/<session-id>.sock`.

use std::path::Path;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tracing::{debug, info, warn};

use crate::command::{Command, CommandResponse};
use crate::server::handler::handle_command;
use crate::server::CommandTx;

/// Maximum allowed line length for incoming NDJSON commands (1 MB).
/// Prevents memory exhaustion from malicious or buggy clients.
const MAX_LINE_LENGTH: usize = 1024 * 1024;

/// Start the Unix socket server.
///
/// Creates the socket file and listens for connections until `shutdown`
/// signals. Each connection is handled in a separate task.
pub async fn serve(
    socket_path: &Path,
    command_tx: CommandTx,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), String> {
    // Ensure the parent directory exists
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("failed to create socket dir: {e}"))?;
    }

    // Remove stale socket file (ignore NotFound to avoid TOCTOU race)
    match std::fs::remove_file(socket_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("failed to remove stale socket: {e}")),
    }

    let listener = UnixListener::bind(socket_path).map_err(|e| {
        format!(
            "failed to bind unix socket at {}: {e}",
            socket_path.display()
        )
    })?;

    info!(path = %socket_path.display(), "started Unix socket control server");

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, _addr)) => {
                        let tx = command_tx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, tx).await {
                                debug!("unix socket connection ended: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        warn!("unix socket accept error: {e}");
                    }
                }
            }
            _ = shutdown.wait_for(|&v| v) => {
                info!("unix socket server shutting down");
                break;
            }
        }
    }

    // Clean up socket file
    let _ = std::fs::remove_file(socket_path);
    Ok(())
}

/// Handle a single client connection.
///
/// Reads NDJSON commands, processes them, and writes NDJSON responses.
async fn handle_connection(
    stream: tokio::net::UnixStream,
    command_tx: CommandTx,
) -> Result<(), String> {
    let (reader, mut writer) = stream.into_split();
    // Cap total readable bytes per connection (10 MB) to prevent next_line()
    // from accumulating unbounded memory on lines without newlines. Generous
    // enough for many commands per persistent connection.
    let mut lines = BufReader::new(reader.take(10 * 1024 * 1024)).lines();

    while let Some(line) = lines.next_line().await.map_err(|e| e.to_string())? {
        if line.len() > MAX_LINE_LENGTH {
            let resp = CommandResponse::error("command too large");
            let mut json = serde_json::to_string(&resp).unwrap_or_default();
            json.push('\n');
            let _ = writer.write_all(json.as_bytes()).await;
            let _ = writer.flush().await;
            return Err("oversized command".into());
        }

        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let command: Command = match serde_json::from_str(&line) {
            Ok(cmd) => cmd,
            Err(e) => {
                let resp = CommandResponse::error(format!("invalid JSON: {e}"));
                let mut json = serde_json::to_string(&resp).unwrap_or_default();
                json.push('\n');
                if writer.write_all(json.as_bytes()).await.is_err() {
                    return Err("client disconnected during error response".into());
                }
                let _ = writer.flush().await;
                continue;
            }
        };

        let response = handle_command(&command_tx, command).await;
        let mut json = serde_json::to_string(&response).map_err(|e| e.to_string())?;
        json.push('\n');
        writer
            .write_all(json.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        writer.flush().await.map_err(|e| e.to_string())?;
    }

    Ok(())
}
