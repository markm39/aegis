//! Terminal spawner: open commands in new terminal windows/tabs.
//!
//! Detects the current terminal environment and spawns new windows using
//! the appropriate mechanism (tmux, iTerm2, Terminal.app, or fallback).

use std::process::Command;

/// Supported terminal backends.
#[derive(Debug, Clone, PartialEq)]
pub enum TerminalBackend {
    /// tmux split/window
    Tmux,
    /// macOS iTerm2 via osascript
    ITerm2,
    /// macOS Terminal.app via osascript
    TerminalApp,
    /// No supported terminal detected
    Unsupported,
}

/// Detect the current terminal backend from environment variables.
pub fn detect_backend() -> TerminalBackend {
    if std::env::var("TMUX").is_ok() {
        return TerminalBackend::Tmux;
    }
    if let Ok(term) = std::env::var("TERM_PROGRAM") {
        match term.as_str() {
            "iTerm.app" => return TerminalBackend::ITerm2,
            "Apple_Terminal" => return TerminalBackend::TerminalApp,
            _ => {}
        }
    }
    // On macOS, Terminal.app is always available even if not detected
    if cfg!(target_os = "macos") {
        return TerminalBackend::TerminalApp;
    }
    TerminalBackend::Unsupported
}

/// Spawn a command in a new terminal window/tab.
///
/// Returns Ok(()) if the spawn was successful, or a message to display
/// if the terminal doesn't support spawning.
pub fn spawn_in_terminal(command: &str) -> Result<(), String> {
    let backend = detect_backend();

    match backend {
        TerminalBackend::Tmux => spawn_tmux(command),
        TerminalBackend::ITerm2 => spawn_iterm2(command),
        TerminalBackend::TerminalApp => spawn_terminal_app(command),
        TerminalBackend::Unsupported => {
            Err(format!("No supported terminal detected. Run in another terminal:\n  {command}"))
        }
    }
}

/// Spawn in a tmux split pane.
fn spawn_tmux(command: &str) -> Result<(), String> {
    let status = Command::new("tmux")
        .args(["split-window", "-h", command])
        .status()
        .map_err(|e| format!("failed to run tmux: {e}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("tmux split-window failed (exit {})", status))
    }
}

/// Spawn in an iTerm2 tab via osascript.
fn spawn_iterm2(command: &str) -> Result<(), String> {
    let script = format!(
        r#"tell application "iTerm2"
            tell current window
                create tab with default profile
                tell current session
                    write text "{}"
                end tell
            end tell
        end tell"#,
        command.replace('"', r#"\""#)
    );

    let status = Command::new("osascript")
        .args(["-e", &script])
        .status()
        .map_err(|e| format!("failed to run osascript: {e}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("iTerm2 osascript failed (exit {})", status))
    }
}

/// Spawn in a Terminal.app window via osascript.
fn spawn_terminal_app(command: &str) -> Result<(), String> {
    let script = format!(
        r#"tell application "Terminal"
            do script "{}"
            activate
        end tell"#,
        command.replace('"', r#"\""#)
    );

    let status = Command::new("osascript")
        .args(["-e", &script])
        .status()
        .map_err(|e| format!("failed to run osascript: {e}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("Terminal.app osascript failed (exit {})", status))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_backend_returns_value() {
        // Just verify it doesn't panic
        let _ = detect_backend();
    }

    #[test]
    fn terminal_backend_variants() {
        // Ensure all variants are distinct
        assert_ne!(TerminalBackend::Tmux, TerminalBackend::ITerm2);
        assert_ne!(TerminalBackend::ITerm2, TerminalBackend::TerminalApp);
        assert_ne!(TerminalBackend::TerminalApp, TerminalBackend::Unsupported);
    }
}
