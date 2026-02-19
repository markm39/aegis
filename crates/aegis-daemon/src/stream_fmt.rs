//! Format agent output streams (plain or JSON) for human-readable display.

use aegis_pilot::json_events::format_json_line;
use aegis_pilot::session::{StreamKind, ToolKind};

/// Format a single output line based on stream kind.
pub fn format_stream_line(kind: &StreamKind, raw: &str) -> Vec<String> {
    match kind {
        StreamKind::Plain => vec![raw.to_string()],
        StreamKind::Json { tool: ToolKind::ClaudeCode } => crate::ndjson_fmt::format_ndjson_line(raw),
        StreamKind::Json { tool: ToolKind::Codex } => format_json_line(ToolKind::Codex, raw),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codex_thread_started() {
        let line = r#"{"type":"thread.started","thread_id":"abc"}"#;
        let out = format_stream_line(&StreamKind::Json { tool: ToolKind::Codex }, line);
        assert_eq!(out, vec!["Session started (thread_id: abc)".to_string()]);
    }

    #[test]
    fn codex_error() {
        let line = r#"{"type":"error","message":"boom"}"#;
        let out = format_stream_line(&StreamKind::Json { tool: ToolKind::Codex }, line);
        assert_eq!(out, vec!["Error: boom".to_string()]);
    }
}
