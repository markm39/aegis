//! Daemon persistence: PID files, launchd integration, and sleep prevention.
//!
//! Handles the OS-level integration needed to keep the daemon running reliably:
//! - PID file management for single-instance enforcement
//! - launchd plist generation and installation for macOS auto-start
//! - caffeinate integration to prevent system sleep during active work

use std::path::PathBuf;

use aegis_types::daemon::{daemon_dir, daemon_pid_path};

/// Write the daemon's PID file. Returns the path written.
pub fn write_pid_file() -> Result<PathBuf, String> {
    let path = daemon_pid_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("failed to create daemon dir: {e}"))?;
    }

    let pid = std::process::id();
    std::fs::write(&path, pid.to_string()).map_err(|e| format!("failed to write PID file: {e}"))?;

    tracing::info!(pid, path = %path.display(), "daemon PID file written");
    Ok(path)
}

/// Read the daemon PID from the PID file.
pub fn read_pid() -> Option<u32> {
    let path = daemon_pid_path();
    let content = std::fs::read_to_string(&path).ok()?;
    content.trim().parse().ok()
}

/// Remove the daemon PID file.
pub fn remove_pid_file() {
    let path = daemon_pid_path();
    if let Err(e) = std::fs::remove_file(&path) {
        tracing::debug!(error = %e, "failed to remove PID file (may not exist)");
    }
}

/// Check whether a process with the given PID is alive.
pub fn is_process_alive(pid: u32) -> bool {
    // Guard against PID values that would wrap negative when cast to i32,
    // which could probe process groups instead of individual processes.
    let Ok(raw_pid) = i32::try_from(pid) else {
        return false;
    };
    // kill(pid, 0) checks existence without sending a signal
    let result = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(raw_pid),
        None, // Signal 0: just check
    );
    result.is_ok()
}

/// Path to the launchd plist file.
pub fn plist_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home)
        .join("Library")
        .join("LaunchAgents")
        .join("com.aegis.daemon.plist")
}

/// Escape XML special characters for safe interpolation into plist XML.
fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Generate a launchd plist XML string for the daemon.
///
/// The plist configures:
/// - `KeepAlive`: auto-restart on crash
/// - `RunAtLoad`: start on login
/// - `ThrottleInterval`: prevent crash loops (10s minimum between restarts)
/// - Stdout/stderr routing to daemon log files
pub fn generate_launchd_plist(aegis_binary: &str) -> String {
    let daemon_dir = daemon_dir();
    let stdout_log = daemon_dir.join("stdout.log");
    let stderr_log = daemon_dir.join("stderr.log");

    let binary_escaped = escape_xml(aegis_binary);
    let stdout_escaped = escape_xml(&stdout_log.display().to_string());
    let stderr_escaped = escape_xml(&stderr_log.display().to_string());

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.aegis.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>{binary_escaped}</string>
        <string>daemon</string>
        <string>run</string>
        <string>--launchd</string>
    </array>
    <key>KeepAlive</key>
    <true/>
    <key>RunAtLoad</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>10</integer>
    <key>StandardOutPath</key>
    <string>{stdout_escaped}</string>
    <key>StandardErrorPath</key>
    <string>{stderr_escaped}</string>
</dict>
</plist>"#
    )
}

/// Install the launchd plist and optionally start the daemon.
pub fn install_launchd(aegis_binary: &str) -> Result<(), String> {
    let plist = plist_path();
    if let Some(parent) = plist.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create LaunchAgents dir: {e}"))?;
    }

    let content = generate_launchd_plist(aegis_binary);
    std::fs::write(&plist, content).map_err(|e| format!("failed to write plist: {e}"))?;

    tracing::info!(path = %plist.display(), "launchd plist installed");
    Ok(())
}

/// Uninstall the launchd plist.
pub fn uninstall_launchd() -> Result<(), String> {
    let plist = plist_path();
    if plist.exists() {
        std::fs::remove_file(&plist).map_err(|e| format!("failed to remove plist: {e}"))?;
        tracing::info!(path = %plist.display(), "launchd plist removed");
    }
    Ok(())
}

/// Spawn `caffeinate -i -w <pid>` to prevent idle sleep while the daemon runs.
///
/// The `-w` flag ties caffeinate to the daemon's PID -- when the daemon exits,
/// caffeinate exits too. Returns the child handle so the caller can reap it
/// during shutdown (preventing zombie processes on long-running daemons).
pub fn start_caffeinate() -> Result<std::process::Child, String> {
    let daemon_pid = std::process::id();
    let child = std::process::Command::new("caffeinate")
        .args(["-i", "-w", &daemon_pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to spawn caffeinate: {e}"))?;

    tracing::info!(
        caffeinate_pid = child.id(),
        daemon_pid,
        "caffeinate started"
    );
    Ok(child)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_plist_contains_key_elements() {
        let plist = generate_launchd_plist("/usr/local/bin/aegis");
        assert!(plist.contains("com.aegis.daemon"));
        assert!(plist.contains("/usr/local/bin/aegis"));
        assert!(plist.contains("<key>KeepAlive</key>"));
        assert!(plist.contains("<key>RunAtLoad</key>"));
        assert!(plist.contains("<key>ThrottleInterval</key>"));
        assert!(plist.contains("stdout.log"));
        assert!(plist.contains("stderr.log"));
    }

    #[test]
    fn escape_xml_clean_string() {
        assert_eq!(escape_xml("/usr/local/bin/aegis"), "/usr/local/bin/aegis");
    }

    #[test]
    fn escape_xml_special_characters() {
        assert_eq!(escape_xml("a&b"), "a&amp;b");
        assert_eq!(escape_xml("a<b"), "a&lt;b");
        assert_eq!(escape_xml("a>b"), "a&gt;b");
        assert_eq!(escape_xml("a\"b"), "a&quot;b");
        assert_eq!(escape_xml("a'b"), "a&apos;b");
    }

    #[test]
    fn escape_xml_injection_attempt() {
        let malicious = "</string><string>evil</string>";
        let escaped = escape_xml(malicious);
        assert!(!escaped.contains("</string>"));
        assert!(escaped.contains("&lt;/string&gt;"));
    }

    #[test]
    fn generate_plist_escapes_binary_path() {
        let plist = generate_launchd_plist("/path/with <special> & chars");
        assert!(plist.contains("&lt;special&gt;"));
        assert!(plist.contains("&amp;"));
        assert!(!plist.contains("<special>"));
    }

    #[test]
    fn plist_path_is_in_launch_agents() {
        let path = plist_path();
        assert!(path.to_string_lossy().contains("LaunchAgents"));
        assert!(path.to_string_lossy().contains("com.aegis.daemon.plist"));
    }

    #[test]
    fn current_process_is_alive() {
        assert!(is_process_alive(std::process::id()));
    }

    #[test]
    fn dead_process_is_not_alive() {
        // PID 99999 is unlikely to exist
        assert!(!is_process_alive(99999));
    }
}
