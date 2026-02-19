//! Format agent output streams (plain or JSON) for human-readable display.

use serde_json::Value;

use aegis_pilot::session::{StreamKind, ToolKind};

/// Format a single output line based on stream kind.
pub fn format_stream_line(kind: &StreamKind, raw: &str) -> Vec<String> {
    match kind {
        StreamKind::Plain => vec![raw.to_string()],
        StreamKind::Json { tool: ToolKind::ClaudeCode } => crate::ndjson_fmt::format_ndjson_line(raw),
        StreamKind::Json { tool: ToolKind::Codex } => format_codex_json_line(raw),
    }
}

fn format_codex_json_line(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return vec![];
    }

    let obj: Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => return vec![raw.to_string()],
    };

    let event_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");

    match event_type {
        "thread.started" => {
            let id = obj.get("thread_id").and_then(|v| v.as_str()).unwrap_or("unknown");
            vec![format!("Session started (thread_id: {id})")]
        }
        "turn.failed" => {
            let msg = obj.get("error").and_then(|v| v.get("message")).and_then(|v| v.as_str())
                .or_else(|| obj.get("message").and_then(|v| v.as_str()))
                .unwrap_or("unknown error");
            vec![format!("Error: {msg}")]
        }
        "error" => {
            let msg = obj.get("message").and_then(|v| v.as_str()).unwrap_or("unknown error");
            vec![format!("Error: {msg}")]
        }
        _ => {
            if let Some(lines) = extract_text_lines(&obj) {
                return lines;
            }
            if event_type.contains("tool") {
                if let Some(name) = obj.get("tool_name").and_then(|v| v.as_str())
                    .or_else(|| obj.get("name").and_then(|v| v.as_str()))
                {
                    return vec![format!("> {name}")];
                }
            }
            vec![]
        }
    }
}

fn extract_text_lines(obj: &Value) -> Option<Vec<String>> {
    if let Some(delta) = obj.get("delta").and_then(|v| v.as_str()) {
        return Some(delta.lines().map(|l| l.to_string()).collect());
    }

    if let Some(text) = obj.get("text").and_then(|v| v.as_str()) {
        return Some(text.lines().map(|l| l.to_string()).collect());
    }

    if let Some(message) = obj.get("message") {
        if let Some(lines) = extract_content_lines(message) {
            return Some(lines);
        }
    }

    if let Some(lines) = extract_content_lines(obj) {
        return Some(lines);
    }

    None
}

fn extract_content_lines(obj: &Value) -> Option<Vec<String>> {
    let content = obj.get("content").and_then(|v| v.as_array())?;
    let mut lines = Vec::new();
    for block in content {
        let block_type = block.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if block_type == "text" || block_type.is_empty() {
            if let Some(text) = block.get("text").and_then(|v| v.as_str()) {
                for line in text.lines() {
                    lines.push(line.to_string());
                }
            }
        }
    }
    if lines.is_empty() { None } else { Some(lines) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codex_thread_started() {
        let line = r#"{"type":"thread.started","thread_id":"abc"}"#;
        let out = format_codex_json_line(line);
        assert_eq!(out, vec!["Session started (thread_id: abc)".to_string()]);
    }

    #[test]
    fn codex_error() {
        let line = r#"{"type":"error","message":"boom"}"#;
        let out = format_codex_json_line(line);
        assert_eq!(out, vec!["Error: boom".to_string()]);
    }
}
