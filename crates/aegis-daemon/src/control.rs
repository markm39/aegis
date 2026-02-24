//! Daemon control socket server.
//!
//! Runs a tokio-based Unix domain socket server in a background thread.
//! Accepts `DaemonCommand`s via NDJSON, forwards them to the daemon's
//! synchronous main loop via a channel, and returns `DaemonResponse`s.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tracing::{debug, info, warn};

use aegis_control::daemon::{DaemonCommand, DaemonResponse};

/// Maximum allowed line length for incoming NDJSON commands (1 MB).
/// Prevents memory exhaustion from malicious or buggy clients.
const MAX_LINE_LENGTH: usize = 1024 * 1024;

/// Channel type for sending commands from the socket server to the daemon loop.
///
/// Uses `std::sync::mpsc` so the daemon main loop can call `recv_timeout()`
/// to wake immediately on incoming commands instead of sleeping between ticks.
/// `std::sync::mpsc::Sender::send()` is non-blocking and safe from async code.
pub type DaemonCmdTx =
    std::sync::mpsc::Sender<(DaemonCommand, tokio::sync::oneshot::Sender<DaemonResponse>)>;
pub type DaemonCmdRx =
    std::sync::mpsc::Receiver<(DaemonCommand, tokio::sync::oneshot::Sender<DaemonResponse>)>;

/// Create a command channel pair for daemon control.
pub fn daemon_cmd_channel() -> (DaemonCmdTx, DaemonCmdRx) {
    std::sync::mpsc::channel()
}

/// Spawn the control socket server in a background thread.
///
/// Accepts a shared `tokio::runtime::Handle` so the server runs on the
/// daemon's shared runtime rather than creating its own thread pool.
///
/// Returns the receiver end of the command channel. The daemon main loop
/// should call `rx.try_recv()` on each tick to process incoming commands.
pub fn spawn_control_server(
    socket_path: PathBuf,
    shutdown: Arc<AtomicBool>,
    rt_handle: tokio::runtime::Handle,
) -> Result<(DaemonCmdTx, DaemonCmdRx), String> {
    let (tx, rx) = daemon_cmd_channel();
    let thread_tx = tx.clone();

    std::thread::Builder::new()
        .name("daemon-control".into())
        .spawn(move || {
            rt_handle.block_on(serve(&socket_path, thread_tx, shutdown));
        })
        .map_err(|e| format!("failed to spawn control server thread: {e}"))?;

    Ok((tx, rx))
}

/// Run the Unix socket server until shutdown.
async fn serve(socket_path: &Path, cmd_tx: DaemonCmdTx, shutdown: Arc<AtomicBool>) {
    // Ensure the parent directory exists
    if let Some(parent) = socket_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            warn!(error = %e, "failed to create socket dir");
            return;
        }
    }

    // Remove stale socket file (unconditional: avoids TOCTOU race with exists()+remove())
    match std::fs::remove_file(socket_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            warn!(
                path = %socket_path.display(),
                error = %e,
                "failed to remove stale socket file"
            );
            return;
        }
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

    // Restrict socket permissions to owner-only (0o600) to prevent other
    // local users from sending commands to the daemon.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) =
            std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
        {
            warn!(
                path = %socket_path.display(),
                error = %e,
                "failed to set daemon socket permissions to 0600"
            );
        }
    }

    info!(path = %socket_path.display(), "daemon control socket listening");

    loop {
        // Check shutdown flag (polled every accept timeout)
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Accept with a timeout so we can check shutdown periodically
        let accept =
            tokio::time::timeout(std::time::Duration::from_secs(1), listener.accept()).await;

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
    // Cap total readable bytes per connection (10 MB) to prevent next_line()
    // from accumulating unbounded memory on lines without newlines. Generous
    // enough for many commands per persistent connection.
    let mut lines = BufReader::new(reader.take(10 * 1024 * 1024)).lines();

    while let Some(line) = lines.next_line().await.map_err(|e| e.to_string())? {
        if line.len() > MAX_LINE_LENGTH {
            let resp = DaemonResponse::error("command too large");
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

        let command: DaemonCommand = match serde_json::from_str(&line) {
            Ok(cmd) => cmd,
            Err(e) => {
                let resp = DaemonResponse::error(format!("invalid JSON: {e}"));
                let mut json = serde_json::to_string(&resp).unwrap_or_default();
                json.push('\n');
                if let Err(write_err) = writer.write_all(json.as_bytes()).await {
                    warn!(error = %write_err, "failed to write error response to control client");
                }
                let _ = writer.flush().await;
                continue;
            }
        };

        let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
        if cmd_tx.send((command, resp_tx)).is_err() {
            let resp = DaemonResponse::error("daemon main loop disconnected");
            let mut json = serde_json::to_string(&resp).unwrap_or_default();
            json.push('\n');
            if let Err(write_err) = writer.write_all(json.as_bytes()).await {
                warn!(error = %write_err, "failed to write disconnect response to control client");
            }
            let _ = writer.flush().await;
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
        writer.flush().await.map_err(|e| e.to_string())?;
    }

    Ok(())
}
