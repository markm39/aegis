//! Daemon control socket server.
//!
//! Runs a tokio-based Unix domain socket server in a background thread.
//! Accepts `DaemonCommand`s via NDJSON, forwards them to the daemon's
//! synchronous main loop via a channel, and returns `DaemonResponse`s.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tracing::{debug, info, warn};

use aegis_control::daemon::{DaemonCommand, DaemonResponse};

/// Channel type for sending commands from the socket server to the daemon loop.
///
/// Each command includes a oneshot sender for the response. The daemon main
/// loop calls `try_recv()` (sync-safe) to drain pending commands on each tick.
pub type DaemonCmdTx =
    tokio::sync::mpsc::Sender<(DaemonCommand, tokio::sync::oneshot::Sender<DaemonResponse>)>;
pub type DaemonCmdRx =
    tokio::sync::mpsc::Receiver<(DaemonCommand, tokio::sync::oneshot::Sender<DaemonResponse>)>;

/// Create a command channel pair for daemon control.
pub fn daemon_cmd_channel(buffer: usize) -> (DaemonCmdTx, DaemonCmdRx) {
    tokio::sync::mpsc::channel(buffer)
}

/// Spawn the control socket server in a background thread.
///
/// Returns the receiver end of the command channel. The daemon main loop
/// should call `rx.try_recv()` on each tick to process incoming commands.
pub fn spawn_control_server(
    socket_path: PathBuf,
    shutdown: Arc<AtomicBool>,
) -> Result<DaemonCmdRx, String> {
    let (tx, rx) = daemon_cmd_channel(64);

    std::thread::Builder::new()
        .name("daemon-control".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime creation failed (out of memory?)");
            rt.block_on(serve(&socket_path, tx, shutdown));
        })
        .map_err(|e| format!("failed to spawn control server thread: {e}"))?;

    Ok(rx)
}

/// Run the Unix socket server until shutdown.
async fn serve(
    socket_path: &Path,
    cmd_tx: DaemonCmdTx,
    shutdown: Arc<AtomicBool>,
) {
    // Ensure the parent directory exists
    if let Some(parent) = socket_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            warn!(error = %e, "failed to create socket dir");
            return;
        }
    }

    // Remove stale socket file
    if socket_path.exists() {
        let _ = std::fs::remove_file(socket_path);
    }

    let listener = match UnixListener::bind(socket_path) {
        Ok(l) => l,
        Err(e) => {
            warn!(
                path = %socket_path.display(),
                error = %e,
                "failed to bind daemon control socket"
            );
            return;
        }
    };

    info!(path = %socket_path.display(), "daemon control socket listening");

    loop {
        // Check shutdown flag (polled every accept timeout)
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Accept with a timeout so we can check shutdown periodically
        let accept = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            listener.accept(),
        )
        .await;

        match accept {
            Ok(Ok((stream, _addr))) => {
                let tx = cmd_tx.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, tx).await {
                        debug!(error = %e, "daemon control connection ended");
                    }
                });
            }
            Ok(Err(e)) => {
                warn!(error = %e, "daemon control socket accept error");
            }
            Err(_) => {
                // Timeout -- loop back to check shutdown
            }
        }
    }

    // Clean up socket file
    let _ = std::fs::remove_file(socket_path);
    info!("daemon control socket stopped");
}

/// Handle a single client connection.
async fn handle_connection(
    stream: tokio::net::UnixStream,
    cmd_tx: DaemonCmdTx,
) -> Result<(), String> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await.map_err(|e| e.to_string())? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let command: DaemonCommand = match serde_json::from_str(&line) {
            Ok(cmd) => cmd,
            Err(e) => {
                let resp = DaemonResponse::error(format!("invalid JSON: {e}"));
                let mut json = serde_json::to_string(&resp).unwrap_or_default();
                json.push('\n');
                if let Err(write_err) = writer.write_all(json.as_bytes()).await {
                    warn!(error = %write_err, "failed to write error response to control client");
                }
                continue;
            }
        };

        let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
        if cmd_tx.send((command, resp_tx)).await.is_err() {
            let resp = DaemonResponse::error("daemon main loop disconnected");
            let mut json = serde_json::to_string(&resp).unwrap_or_default();
            json.push('\n');
            if let Err(write_err) = writer.write_all(json.as_bytes()).await {
                warn!(error = %write_err, "failed to write disconnect response to control client");
            }
            break;
        }

        let response = match resp_rx.await {
            Ok(resp) => resp,
            Err(_) => DaemonResponse::error("response channel dropped"),
        };

        let mut json = serde_json::to_string(&response).map_err(|e| e.to_string())?;
        json.push('\n');
        writer
            .write_all(json.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
    }

    Ok(())
}
