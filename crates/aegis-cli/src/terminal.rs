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
        TerminalBackend::Unsupported => Err(format!(
            "No supported terminal detected. Run in another terminal:\n  {command}"
        )),
    }
}

/// Open a URL in the system default browser.
pub fn open_url(url: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg(url)
            .status()
            .map_err(|e| format!("failed to open browser: {e}"))?;
        Ok(())
    }
    #[cfg(target_os = "windows")]
    {
        Command::new("cmd")
            .args(["/C", "start", "", url])
            .status()
            .map_err(|e| format!("failed to open browser: {e}"))?;
        Ok(())
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Command::new("xdg-open")
            .arg(url)
            .status()
            .map_err(|e| format!("failed to open browser: {e}"))?;
        Ok(())
    }
}

/// Spawn in a tmux split pane.
fn spawn_tmux(command: &str) -> Result<(), String> {
    let output = Command::new("tmux")
        .args(["split-window", "-h", command])
        .output()
        .map_err(|e| format!("failed to run tmux: {e}"))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = stderr.trim();
        if detail.is_empty() {
            Err(format!("tmux split-window failed (exit {})", output.status))
        } else {
            Err(format!("tmux split-window failed: {detail}"))
        }
    }
}

/// Shell-quote a string with single quotes so it survives shell expansion.
///
/// Wraps the string in single quotes and escapes any embedded single quotes
/// using the `'\''` idiom (end quote, escaped quote, start quote).
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Escape a string for use inside an AppleScript double-quoted literal.
///
/// Escapes backslashes, double quotes, newlines, carriage returns, and tabs.
/// Order matters: backslashes must be escaped first to avoid double-escaping.
fn escape_applescript(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

/// Run an AppleScript via osascript, capturing stderr for error messages.
fn run_applescript(script: &str, label: &str) -> Result<(), String> {
    let output = Command::new("osascript")
        .args(["-e", script])
        .output()
        .map_err(|e| format!("failed to run osascript: {e}"))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = stderr.trim();
        if detail.is_empty() {
            Err(format!("{label} osascript failed (exit {})", output.status))
        } else {
            Err(format!("{label}: {detail}"))
        }
    }
}

/// Spawn in an iTerm2 tab via osascript.
///
/// If iTerm2 has no open windows, creates a new window first.
fn spawn_iterm2(command: &str) -> Result<(), String> {
    let escaped = escape_applescript(command);
    let script = format!(
        r#"tell application "iTerm2"
            if (count of windows) = 0 then
                create window with default profile
            else
                tell current window
                    create tab with default profile
                end tell
            end if
            tell current window
                tell current session
                    write text "{escaped}"
                end tell
            end tell
        end tell"#,
    );

    run_applescript(&script, "iTerm2")
}

/// Spawn in a Terminal.app window via osascript.
fn spawn_terminal_app(command: &str) -> Result<(), String> {
    let escaped = escape_applescript(command);
    let script = format!(
        r#"tell application "Terminal"
            do script "{escaped}"
            activate
        end tell"#,
    );

    run_applescript(&script, "Terminal.app")
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

    #[test]
    fn escape_applescript_no_special_chars() {
        assert_eq!(
            escape_applescript("aegis daemon status"),
            "aegis daemon status"
        );
    }

    #[test]
    fn escape_applescript_double_quotes() {
        assert_eq!(
            escape_applescript(r#"aegis wrap -- echo "hello""#),
            r#"aegis wrap -- echo \"hello\""#
        );
    }

    #[test]
    fn escape_applescript_backslashes() {
        assert_eq!(
            escape_applescript(r"aegis wrap -- echo path\to\file"),
            r"aegis wrap -- echo path\\to\\file"
        );
    }

    #[test]
    fn escape_applescript_mixed() {
        // Both backslashes and quotes
        assert_eq!(
            escape_applescript(r#"echo "back\slash""#),
            r#"echo \"back\\slash\""#
        );
    }

    #[test]
    fn escape_applescript_newlines() {
        assert_eq!(
            escape_applescript("line1\nline2\rline3"),
            "line1\\nline2\\rline3"
        );
    }

    #[test]
    fn escape_applescript_tabs() {
        assert_eq!(escape_applescript("col1\tcol2"), "col1\\tcol2");
    }

    #[test]
    fn unsupported_backend_returns_helpful_error() {
        let result = spawn_in_terminal("test command");
        // In CI/test environments, might be unsupported
        if let Err(msg) = result {
            if msg.contains("No supported terminal") {
                assert!(msg.contains("test command"));
            }
        }
    }

    #[test]
    fn shell_quote_simple() {
        assert_eq!(shell_quote("hello"), "'hello'");
    }

    #[test]
    fn shell_quote_spaces() {
        assert_eq!(shell_quote("/path/with spaces"), "'/path/with spaces'");
    }

    #[test]
    fn shell_quote_single_quotes() {
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn shell_quote_empty() {
        assert_eq!(shell_quote(""), "''");
    }
}
