//! OS service installer for the Aegis daemon.
//!
//! Provides a unified interface for installing the daemon as a system service:
//! - **macOS**: launchd plist in `~/Library/LaunchAgents/`
//! - **Linux**: systemd user service in `~/.config/systemd/user/`
//!
//! Supports install, uninstall, start, stop, restart, and status queries.

use std::path::PathBuf;
use std::process::Command;

/// Current state of the daemon service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceStatus {
    /// Service is installed and running.
    Running,
    /// Service is installed but not running.
    Stopped,
    /// Service is not installed.
    NotInstalled,
    /// Status could not be determined.
    Unknown,
}

impl std::fmt::Display for ServiceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Running => write!(f, "running"),
            Self::Stopped => write!(f, "stopped"),
            Self::NotInstalled => write!(f, "not installed"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Result of a service operation.
#[derive(Debug)]
pub struct ServiceResult {
    pub success: bool,
    pub message: String,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Install the daemon as an OS service.
pub fn install(aegis_binary: &str) -> ServiceResult {
    if cfg!(target_os = "macos") {
        install_launchd(aegis_binary)
    } else if cfg!(target_os = "linux") {
        install_systemd(aegis_binary)
    } else {
        ServiceResult {
            success: false,
            message: "service installation not supported on this platform".to_string(),
        }
    }
}

/// Uninstall the daemon service.
pub fn uninstall() -> ServiceResult {
    if cfg!(target_os = "macos") {
        uninstall_launchd()
    } else if cfg!(target_os = "linux") {
        uninstall_systemd()
    } else {
        ServiceResult {
            success: false,
            message: "service uninstall not supported on this platform".to_string(),
        }
    }
}

/// Start the daemon service.
pub fn start() -> ServiceResult {
    if cfg!(target_os = "macos") {
        start_launchd()
    } else if cfg!(target_os = "linux") {
        start_systemd()
    } else {
        ServiceResult {
            success: false,
            message: "service start not supported on this platform".to_string(),
        }
    }
}

/// Stop the daemon service.
pub fn stop() -> ServiceResult {
    if cfg!(target_os = "macos") {
        stop_launchd()
    } else if cfg!(target_os = "linux") {
        stop_systemd()
    } else {
        ServiceResult {
            success: false,
            message: "service stop not supported on this platform".to_string(),
        }
    }
}

/// Restart the daemon service (stop + start).
pub fn restart() -> ServiceResult {
    let _ = stop();
    start()
}

/// Query current service status.
pub fn status() -> ServiceStatus {
    if cfg!(target_os = "macos") {
        status_launchd()
    } else if cfg!(target_os = "linux") {
        status_systemd()
    } else {
        ServiceStatus::Unknown
    }
}

/// Check whether the service is installed (plist/unit file exists).
pub fn is_installed() -> bool {
    if cfg!(target_os = "macos") {
        launchd_plist_path().exists()
    } else if cfg!(target_os = "linux") {
        systemd_unit_path().exists()
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// macOS: launchd
// ---------------------------------------------------------------------------

const LAUNCHD_LABEL: &str = "com.aegis.daemon";

fn launchd_plist_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home)
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{LAUNCHD_LABEL}.plist"))
}

fn install_launchd(aegis_binary: &str) -> ServiceResult {
    let plist_path = launchd_plist_path();

    // Create parent directory.
    if let Some(parent) = plist_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return ServiceResult {
                success: false,
                message: format!("failed to create LaunchAgents dir: {e}"),
            };
        }
    }

    // Generate plist content using the existing function.
    let content = super::persistence::generate_launchd_plist(aegis_binary);

    if let Err(e) = std::fs::write(&plist_path, content) {
        return ServiceResult {
            success: false,
            message: format!("failed to write plist: {e}"),
        };
    }

    // Load the service.
    let output = Command::new("launchctl")
        .args(["load", "-w"])
        .arg(&plist_path)
        .output();

    match output {
        Ok(o) if o.status.success() => ServiceResult {
            success: true,
            message: format!("installed and loaded: {}", plist_path.display()),
        },
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            // "already loaded" is not an error.
            if stderr.contains("already loaded") || stderr.contains("service already loaded") {
                ServiceResult {
                    success: true,
                    message: format!(
                        "plist written (service was already loaded): {}",
                        plist_path.display()
                    ),
                }
            } else {
                ServiceResult {
                    success: false,
                    message: format!("plist written but launchctl load failed: {stderr}"),
                }
            }
        }
        Err(e) => ServiceResult {
            success: false,
            message: format!("plist written but failed to run launchctl: {e}"),
        },
    }
}

fn uninstall_launchd() -> ServiceResult {
    let plist_path = launchd_plist_path();
    if !plist_path.exists() {
        return ServiceResult {
            success: true,
            message: "service not installed (no plist found)".to_string(),
        };
    }

    // Unload first.
    let _ = Command::new("launchctl")
        .args(["unload", "-w"])
        .arg(&plist_path)
        .output();

    // Remove plist file.
    if let Err(e) = std::fs::remove_file(&plist_path) {
        return ServiceResult {
            success: false,
            message: format!("failed to remove plist: {e}"),
        };
    }

    ServiceResult {
        success: true,
        message: "service uninstalled".to_string(),
    }
}

fn start_launchd() -> ServiceResult {
    let output = Command::new("launchctl")
        .args(["start", LAUNCHD_LABEL])
        .output();

    match output {
        Ok(o) if o.status.success() => ServiceResult {
            success: true,
            message: "service started".to_string(),
        },
        Ok(o) => ServiceResult {
            success: false,
            message: format!(
                "launchctl start failed: {}",
                String::from_utf8_lossy(&o.stderr)
            ),
        },
        Err(e) => ServiceResult {
            success: false,
            message: format!("failed to run launchctl: {e}"),
        },
    }
}

fn stop_launchd() -> ServiceResult {
    let output = Command::new("launchctl")
        .args(["stop", LAUNCHD_LABEL])
        .output();

    match output {
        Ok(o) if o.status.success() => ServiceResult {
            success: true,
            message: "service stopped".to_string(),
        },
        Ok(o) => ServiceResult {
            success: false,
            message: format!(
                "launchctl stop failed: {}",
                String::from_utf8_lossy(&o.stderr)
            ),
        },
        Err(e) => ServiceResult {
            success: false,
            message: format!("failed to run launchctl: {e}"),
        },
    }
}

fn status_launchd() -> ServiceStatus {
    let plist_path = launchd_plist_path();
    if !plist_path.exists() {
        return ServiceStatus::NotInstalled;
    }

    let output = Command::new("launchctl")
        .args(["list", LAUNCHD_LABEL])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            // launchctl list output includes PID if running.
            // Format: "PID\tStatus\tLabel" or "-\tStatus\tLabel" if not running.
            if stdout.contains(LAUNCHD_LABEL) {
                // Check if PID field is a number (running) or "-" (stopped).
                if let Some(first_field) = stdout.lines().last().and_then(|l| l.split('\t').next())
                {
                    if first_field.trim().parse::<u32>().is_ok() {
                        return ServiceStatus::Running;
                    }
                }
                ServiceStatus::Stopped
            } else {
                ServiceStatus::Stopped
            }
        }
        _ => ServiceStatus::Stopped,
    }
}

// ---------------------------------------------------------------------------
// Linux: systemd
// ---------------------------------------------------------------------------

const SYSTEMD_UNIT_NAME: &str = "aegis-daemon.service";

fn systemd_unit_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home)
        .join(".config")
        .join("systemd")
        .join("user")
        .join(SYSTEMD_UNIT_NAME)
}

/// Generate a systemd user service unit file.
fn generate_systemd_unit(aegis_binary: &str) -> String {
    let daemon_dir = aegis_types::daemon::daemon_dir();
    format!(
        r#"[Unit]
Description=Aegis Fleet Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={aegis_binary} daemon run
WorkingDirectory={working_dir}
Restart=on-failure
RestartSec=10
StandardOutput=append:{working_dir}/stdout.log
StandardError=append:{working_dir}/stderr.log

# Hardening
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths={working_dir}

[Install]
WantedBy=default.target
"#,
        working_dir = daemon_dir.display()
    )
}

fn install_systemd(aegis_binary: &str) -> ServiceResult {
    let unit_path = systemd_unit_path();

    // Create parent directory.
    if let Some(parent) = unit_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return ServiceResult {
                success: false,
                message: format!("failed to create systemd user dir: {e}"),
            };
        }
    }

    let content = generate_systemd_unit(aegis_binary);
    if let Err(e) = std::fs::write(&unit_path, content) {
        return ServiceResult {
            success: false,
            message: format!("failed to write unit file: {e}"),
        };
    }

    // Reload systemd and enable the service.
    let reload = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .output();

    if let Err(e) = reload {
        return ServiceResult {
            success: false,
            message: format!("unit file written but systemctl daemon-reload failed: {e}"),
        };
    }

    let enable = Command::new("systemctl")
        .args(["--user", "enable", SYSTEMD_UNIT_NAME])
        .output();

    match enable {
        Ok(o) if o.status.success() => ServiceResult {
            success: true,
            message: format!("installed and enabled: {}", unit_path.display()),
        },
        Ok(o) => ServiceResult {
            success: false,
            message: format!(
                "unit written but enable failed: {}",
                String::from_utf8_lossy(&o.stderr)
            ),
        },
        Err(e) => ServiceResult {
            success: false,
            message: format!("unit written but failed to run systemctl: {e}"),
        },
    }
}

fn uninstall_systemd() -> ServiceResult {
    // Disable and stop.
    let _ = Command::new("systemctl")
        .args(["--user", "disable", "--now", SYSTEMD_UNIT_NAME])
        .output();

    let unit_path = systemd_unit_path();
    if unit_path.exists() {
        if let Err(e) = std::fs::remove_file(&unit_path) {
            return ServiceResult {
                success: false,
                message: format!("failed to remove unit file: {e}"),
            };
        }
    }

    // Reload after removing unit.
    let _ = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .output();

    ServiceResult {
        success: true,
        message: "service uninstalled".to_string(),
    }
}

fn start_systemd() -> ServiceResult {
    let output = Command::new("systemctl")
        .args(["--user", "start", SYSTEMD_UNIT_NAME])
        .output();

    match output {
        Ok(o) if o.status.success() => ServiceResult {
            success: true,
            message: "service started".to_string(),
        },
        Ok(o) => ServiceResult {
            success: false,
            message: format!(
                "systemctl start failed: {}",
                String::from_utf8_lossy(&o.stderr)
            ),
        },
        Err(e) => ServiceResult {
            success: false,
            message: format!("failed to run systemctl: {e}"),
        },
    }
}

fn stop_systemd() -> ServiceResult {
    let output = Command::new("systemctl")
        .args(["--user", "stop", SYSTEMD_UNIT_NAME])
        .output();

    match output {
        Ok(o) if o.status.success() => ServiceResult {
            success: true,
            message: "service stopped".to_string(),
        },
        Ok(o) => ServiceResult {
            success: false,
            message: format!(
                "systemctl stop failed: {}",
                String::from_utf8_lossy(&o.stderr)
            ),
        },
        Err(e) => ServiceResult {
            success: false,
            message: format!("failed to run systemctl: {e}"),
        },
    }
}

fn status_systemd() -> ServiceStatus {
    let unit_path = systemd_unit_path();
    if !unit_path.exists() {
        return ServiceStatus::NotInstalled;
    }

    let output = Command::new("systemctl")
        .args(["--user", "is-active", SYSTEMD_UNIT_NAME])
        .output();

    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout).trim().to_string();
            match stdout.as_str() {
                "active" => ServiceStatus::Running,
                "inactive" | "failed" | "deactivating" => ServiceStatus::Stopped,
                _ => ServiceStatus::Unknown,
            }
        }
        Err(_) => ServiceStatus::Unknown,
    }
}

/// Check if systemd user services are available (Linux only).
pub fn is_systemd_available() -> bool {
    if !cfg!(target_os = "linux") {
        return false;
    }
    Command::new("systemctl")
        .args(["--user", "status"])
        .output()
        .map(|o| o.status.success() || o.status.code() == Some(3)) // 3 = no units loaded
        .unwrap_or(false)
}

/// Check if systemd lingering is enabled for the current user.
/// Without lingering, user services stop on logout.
pub fn is_lingering_enabled() -> bool {
    if !cfg!(target_os = "linux") {
        return false;
    }
    let user = std::env::var("USER").unwrap_or_default();
    if user.is_empty() {
        return false;
    }
    let linger_path = PathBuf::from("/var/lib/systemd/linger").join(&user);
    linger_path.exists()
}

/// Enable systemd lingering for the current user.
pub fn enable_lingering() -> ServiceResult {
    let output = Command::new("loginctl").args(["enable-linger"]).output();

    match output {
        Ok(o) if o.status.success() => ServiceResult {
            success: true,
            message: "lingering enabled".to_string(),
        },
        Ok(o) => ServiceResult {
            success: false,
            message: format!(
                "enable-linger failed: {}",
                String::from_utf8_lossy(&o.stderr)
            ),
        },
        Err(e) => ServiceResult {
            success: false,
            message: format!("failed to run loginctl: {e}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launchd_plist_path_is_valid() {
        let path = launchd_plist_path();
        let path_str = path.to_string_lossy();
        assert!(path_str.contains("LaunchAgents"));
        assert!(path_str.ends_with("com.aegis.daemon.plist"));
    }

    #[test]
    fn systemd_unit_path_is_valid() {
        let path = systemd_unit_path();
        let path_str = path.to_string_lossy();
        assert!(path_str.contains("systemd/user"));
        assert!(path_str.ends_with("aegis-daemon.service"));
    }

    #[test]
    fn generate_systemd_unit_contains_required_sections() {
        let unit = generate_systemd_unit("/usr/local/bin/aegis");
        assert!(unit.contains("[Unit]"));
        assert!(unit.contains("[Service]"));
        assert!(unit.contains("[Install]"));
        assert!(unit.contains("/usr/local/bin/aegis"));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("WantedBy=default.target"));
    }

    #[test]
    fn service_status_display() {
        assert_eq!(ServiceStatus::Running.to_string(), "running");
        assert_eq!(ServiceStatus::Stopped.to_string(), "stopped");
        assert_eq!(ServiceStatus::NotInstalled.to_string(), "not installed");
    }
}
