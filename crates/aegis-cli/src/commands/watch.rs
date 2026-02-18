//! Continuous background filesystem monitoring daemon.
//!
//! `aegis watch [--dir PATH] [--policy POLICY] [--name NAME] [--tag TAG]`
//!
//! Watches a directory for filesystem changes and logs all activity to the
//! audit ledger with policy evaluation. Unlike `aegis wrap`, this does not
//! wrap a command -- it runs as a persistent background observer that works
//! with any agent or process modifying the watched directory.
//!
//! Uses the same wrap config infrastructure (`~/.aegis/wraps/<name>/`) so
//! that `aegis status`, `aegis monitor`, and `aegis log` work seamlessly.

use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tracing::info;

use aegis_ledger::AuditStore;
use aegis_policy::PolicyEngine;
use aegis_types::ObserverConfig;

use crate::commands::wrap;

/// Name of the PID file written by watch mode.
const PID_FILENAME: &str = "watch.pid";

/// Interval between checks for the shutdown signal.
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Delay before stopping observer to let late FSEvents arrive.
const FSEVENT_DELIVERY_DELAY: Duration = Duration::from_millis(500);

/// Contents of the PID file written by a running watch process.
#[derive(Debug, Serialize, Deserialize)]
pub struct WatchPidFile {
    pub pid: u32,
    pub started_at: String,
    pub directory: String,
}

/// Run the `aegis watch` command.
pub fn run(
    dir: Option<&Path>,
    policy: &str,
    name: Option<&str>,
    tag: Option<&str>,
    _idle_timeout: u64,
    stop: bool,
) -> Result<()> {
    let project_dir = match dir {
        Some(d) => d
            .canonicalize()
            .with_context(|| format!("--dir path does not exist: {}", d.display()))?,
        None => std::env::current_dir().context("failed to get current directory")?,
    };

    if !project_dir.is_dir() {
        bail!("--dir is not a directory: {}", project_dir.display());
    }

    let derived_name = match name {
        Some(n) => n.to_string(),
        None => derive_watch_name(&project_dir),
    };

    aegis_types::validate_config_name(&derived_name)
        .with_context(|| format!("invalid config name: {derived_name:?}"))?;

    let wrap_dir = wrap::wraps_base_dir()?.join(&derived_name);

    if stop {
        return stop_watch(&wrap_dir, &derived_name);
    }

    run_watch(&wrap_dir, &derived_name, policy, &project_dir, tag)
}

/// Derive a config name from a directory path.
///
/// Uses the last path component: `/Users/mark/myproject` -> `myproject`.
fn derive_watch_name(dir: &Path) -> String {
    dir.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "watch".to_string())
}

/// Run the watch daemon: observe a directory until ctrl-c.
fn run_watch(
    wrap_dir: &Path,
    name: &str,
    policy: &str,
    project_dir: &Path,
    tag: Option<&str>,
) -> Result<()> {
    // Check for already-running watch
    let pid_path = wrap_dir.join(PID_FILENAME);
    if pid_path.exists() {
        if let Ok(existing) = read_pid_file(&pid_path) {
            if is_process_alive(existing.pid) {
                bail!(
                    "watch already running for '{}' (PID {}). Use `aegis watch --name {} --stop` to stop it.",
                    name, existing.pid, name
                );
            }
            // Stale PID file -- remove it
            let _ = fs::remove_file(&pid_path);
        }
    }

    // Ensure wrap config exists (reuse or create)
    let config = wrap::ensure_wrap_config(wrap_dir, name, policy, project_dir)?;

    // Set as current config
    crate::commands::use_config::set_current(name)?;

    // Write PID file
    write_pid_file(&pid_path, project_dir)?;

    // Initialize policy engine
    let policy_dir = config
        .policy_paths
        .first()
        .context("no policy paths configured")?;
    let policy_engine =
        PolicyEngine::new(policy_dir, None).context("failed to initialize policy engine")?;
    info!(policy_dir = %policy_dir.display(), "policy engine loaded");

    // Initialize audit store
    let mut store =
        AuditStore::open(&config.ledger_path).context("failed to open audit store")?;
    info!(ledger_path = %config.ledger_path.display(), "audit store opened");

    // Begin session
    let dir_str = project_dir.to_string_lossy().to_string();
    let session_id = store
        .begin_session(name, "watch", &[dir_str], tag)
        .context("failed to begin audit session")?;
    info!(%session_id, "watch session started");

    // Record policy snapshot
    super::pipeline::record_policy_snapshot(&mut store, &config, &session_id);

    let policy_arc = Arc::new(Mutex::new(policy_engine));
    let store_arc = Arc::new(Mutex::new(store));

    // Start observer
    let observer_session = match &config.observer {
        ObserverConfig::FsEvents { .. } | ObserverConfig::None => {
            // Watch mode always uses FsEvents regardless of config.observer,
            // but with snapshots disabled (continuous monitoring doesn't benefit
            // from pre/post diffing).
            aegis_observer::start_observer(
                &config.sandbox_dir,
                Arc::clone(&store_arc),
                Arc::clone(&policy_arc),
                name,
                Some(session_id),
                false, // no snapshots for continuous watch
            )
            .context("failed to start filesystem observer")?
        }
        ObserverConfig::EndpointSecurity => {
            bail!("EndpointSecurity observer is not yet implemented");
        }
    };

    println!("Watching: {}", project_dir.display());
    println!("Config:   {name}");
    println!("Session:  {session_id}");
    if let Some(t) = tag {
        println!("Tag:      {t}");
    }
    println!("Press Ctrl-C to stop.");

    // Handle both SIGINT (Ctrl-C) and SIGTERM (from --stop)
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = Arc::clone(&shutdown);
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::SeqCst);
    })
    .context("failed to set ctrl-c handler")?;

    // Also handle SIGTERM so `aegis watch --stop` triggers graceful shutdown
    install_sigterm_handler(&shutdown);

    while !shutdown.load(Ordering::SeqCst) {
        std::thread::sleep(POLL_INTERVAL);
    }

    println!("\nShutting down...");

    // Brief delay for late FSEvents
    std::thread::sleep(FSEVENT_DELIVERY_DELAY);

    // Stop observer
    let summary = aegis_observer::stop_observer(observer_session)
        .map_err(|e| anyhow::anyhow!("failed to stop observer: {e}"))?;

    info!(
        fsevents = summary.fsevents_count,
        total = summary.total_logged,
        "observer stopped"
    );

    // End session
    store_arc
        .lock()
        .map_err(|e| anyhow::anyhow!("lock poisoned: {e}"))?
        .end_session(&session_id, 0)
        .context("failed to end audit session")?;

    // Remove PID file
    let _ = fs::remove_file(&pid_path);

    // Print summary
    print_summary(&store_arc, &session_id, &summary);

    Ok(())
}

/// Stop a running watch process by reading its PID file and sending SIGTERM.
fn stop_watch(wrap_dir: &Path, name: &str) -> Result<()> {
    let pid_path = wrap_dir.join(PID_FILENAME);

    if !pid_path.exists() {
        bail!("no watch running for '{name}' (no PID file found)");
    }

    let pid_info = read_pid_file(&pid_path)
        .with_context(|| format!("failed to read PID file: {}", pid_path.display()))?;

    if !is_process_alive(pid_info.pid) {
        // Stale PID file
        let _ = fs::remove_file(&pid_path);
        bail!(
            "watch for '{name}' is not running (stale PID file for PID {}, removed)",
            pid_info.pid
        );
    }

    // Send SIGTERM
    send_sigterm(pid_info.pid)?;
    println!(
        "Sent stop signal to watch '{}' (PID {})",
        name, pid_info.pid
    );

    Ok(())
}

/// Write the PID file for a running watch process.
fn write_pid_file(path: &Path, directory: &Path) -> Result<()> {
    let pid_info = WatchPidFile {
        pid: std::process::id(),
        started_at: chrono::Utc::now().to_rfc3339(),
        directory: directory.to_string_lossy().into_owned(),
    };

    let content =
        serde_json::to_string_pretty(&pid_info).context("failed to serialize PID file")?;
    fs::write(path, content)
        .with_context(|| format!("failed to write PID file: {}", path.display()))?;

    Ok(())
}

/// Read and parse a watch PID file.
pub fn read_pid_file(path: &Path) -> Result<WatchPidFile> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read PID file: {}", path.display()))?;
    serde_json::from_str(&content)
        .with_context(|| format!("failed to parse PID file: {}", path.display()))
}

/// Check if a process is still running.
pub fn is_process_alive(pid: u32) -> bool {
    // pid_t is i32; reject PIDs above i32::MAX to avoid wrapping negative,
    // which would make kill() target a process group instead of a process.
    let Ok(pid_t) = libc::pid_t::try_from(pid) else {
        return false;
    };
    // kill(pid, 0) checks process existence without sending a signal
    unsafe { libc::kill(pid_t, 0) == 0 }
}

/// Send SIGTERM to a process.
fn send_sigterm(pid: u32) -> Result<()> {
    let pid_t = libc::pid_t::try_from(pid)
        .map_err(|_| anyhow::anyhow!("PID {pid} exceeds i32::MAX, refusing to signal"))?;
    let result = unsafe { libc::kill(pid_t, libc::SIGTERM) };
    if result != 0 {
        bail!(
            "failed to send SIGTERM to PID {}: {}",
            pid,
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

/// Install a SIGTERM handler that triggers the same shutdown flag as ctrl-c.
///
/// The `ctrlc` crate only handles SIGINT. When `--stop` sends SIGTERM, we
/// need this handler to trigger graceful shutdown with cleanup.
fn install_sigterm_handler(shutdown: &Arc<AtomicBool>) {
    // Leak an Arc clone to get a 'static pointer for the signal handler.
    // This is intentional -- the process is shutting down when this fires.
    let shutdown_ptr = Arc::into_raw(Arc::clone(shutdown));

    unsafe {
        SHUTDOWN_PTR.store(shutdown_ptr as *mut (), Ordering::SeqCst);
        libc::signal(libc::SIGTERM, sigterm_handler as *const () as libc::sighandler_t);
    }
}

static SHUTDOWN_PTR: std::sync::atomic::AtomicPtr<()> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

extern "C" fn sigterm_handler(_sig: libc::c_int) {
    let ptr = SHUTDOWN_PTR.load(Ordering::SeqCst);
    if !ptr.is_null() {
        // Safety: ptr was created from Arc::into_raw and points to a valid AtomicBool
        let flag = unsafe { &*(ptr as *const AtomicBool) };
        flag.store(true, Ordering::SeqCst);
    }
}

// record_policy_snapshot is reused from pipeline module -- see super::pipeline::record_policy_snapshot

/// Print the post-watch summary.
fn print_summary(
    store_arc: &Arc<Mutex<AuditStore>>,
    session_id: &uuid::Uuid,
    observer_summary: &aegis_observer::ObserverSummary,
) {
    println!("Session:  {session_id}");

    let store_lock = match store_arc.lock() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "failed to lock store for summary");
            return;
        }
    };

    if let Ok(Some(session)) = store_lock.get_session(session_id) {
        if let Some(t) = &session.tag {
            println!("Tag:      {t}");
        }
        println!(
            "Session actions: {} total, {} denied",
            session.total_actions, session.denied_actions
        );
    }

    if observer_summary.total_logged > 0 {
        println!(
            "Observer: {} file events captured",
            observer_summary.total_logged,
        );
    } else {
        println!("Observer: no file events captured");
    }
}

/// Scan for active watch processes across all wrap configs.
///
/// Returns a list of (name, pid_info) for each active watch.
pub fn find_active_watches() -> Vec<(String, WatchPidFile)> {
    let wraps_dir = match wrap::wraps_base_dir() {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };

    let entries = match fs::read_dir(&wraps_dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut active = Vec::new();
    for entry in entries.flatten() {
        let pid_path = entry.path().join(PID_FILENAME);
        if pid_path.exists() {
            if let Ok(pid_info) = read_pid_file(&pid_path) {
                if is_process_alive(pid_info.pid) {
                    let name = entry
                        .file_name()
                        .to_string_lossy()
                        .into_owned();
                    active.push((name, pid_info));
                } else {
                    // Clean up stale PID file
                    let _ = fs::remove_file(&pid_path);
                }
            }
        }
    }

    active
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_watch_name_from_dir() {
        assert_eq!(
            derive_watch_name(Path::new("/Users/mark/myproject")),
            "myproject"
        );
        assert_eq!(
            derive_watch_name(Path::new("/tmp/test-dir")),
            "test-dir"
        );
    }

    #[test]
    fn derive_watch_name_fallback() {
        // Root path has no file_name component
        assert_eq!(derive_watch_name(Path::new("/")), "watch");
    }

    #[test]
    fn write_and_read_pid_file() {
        let tmpdir = tempfile::tempdir().expect("temp dir");
        let pid_path = tmpdir.path().join("watch.pid");

        write_pid_file(&pid_path, Path::new("/tmp/project")).expect("write should succeed");

        let pid_info = read_pid_file(&pid_path).expect("read should succeed");
        assert_eq!(pid_info.pid, std::process::id());
        assert_eq!(pid_info.directory, "/tmp/project");
        assert!(!pid_info.started_at.is_empty());
    }

    #[test]
    fn read_pid_file_missing() {
        let result = read_pid_file(Path::new("/nonexistent/watch.pid"));
        assert!(result.is_err());
    }

    #[test]
    fn is_process_alive_self() {
        // Our own process should be alive
        assert!(is_process_alive(std::process::id()));
    }

    #[test]
    fn is_process_alive_nonexistent() {
        // PID 0 is the kernel; a very high PID is unlikely to exist
        assert!(!is_process_alive(4_000_000_000));
    }

    #[test]
    fn cleanup_removes_pid_file() {
        let tmpdir = tempfile::tempdir().expect("temp dir");
        let pid_path = tmpdir.path().join("watch.pid");

        write_pid_file(&pid_path, Path::new("/tmp/test")).expect("write");
        assert!(pid_path.exists());

        fs::remove_file(&pid_path).expect("remove");
        assert!(!pid_path.exists());
    }

    #[test]
    fn find_active_watches_empty() {
        // Should not panic even if wraps dir doesn't exist
        let watches = find_active_watches();
        // We can't assert it's empty since there might be real watches running,
        // but we can assert it doesn't panic and returns a Vec
        assert!(watches.len() < 1000, "sanity check");
    }
}
