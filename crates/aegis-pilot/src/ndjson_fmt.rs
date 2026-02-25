//! Format Claude Code stream-json NDJSON output for human-readable display.
//!
//! Claude Code's `--output-format stream-json` emits one JSON object per line.
//! This module converts those raw JSON lines into formatted display lines that
//! mirror Claude Code's own TUI presentation: tool call summaries, assistant
//! text, session info, and result summaries.

use serde_json::Value;

/// Format a single NDJSON line into zero or more display lines.
///
/// Returns an empty vec for events we intentionally skip (e.g., user tool
/// results, thinking blocks). Returns the raw line wrapped in a vec if parsing
/// fails (graceful degradation).
pub fn format_ndjson_line(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return vec![];
    }

    let obj: Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => return vec![raw.to_string()],
    };

    let event_type = obj["type"].as_str().unwrap_or("");

    match event_type {
        "system" => format_system(&obj),
        "assistant" => format_assistant(&obj),
        "user" => vec![], // tool results are verbose; the tool call tells the story
        "result" => format_result(&obj),
        _ => vec![], // unknown event types silently skipped
    }
}

/// Format a system event (init, compact_boundary, etc.).
fn format_system(obj: &Value) -> Vec<String> {
    let subtype = obj["subtype"].as_str().unwrap_or("");
    match subtype {
        "init" => {
            let model = obj["model"].as_str().unwrap_or("unknown");
            let cwd = obj["cwd"].as_str().unwrap_or("");
            if cwd.is_empty() {
                vec![format!("Session started (model: {model})")]
            } else {
                vec![format!("Session started (model: {model}, cwd: {cwd})")]
            }
        }
        "compact_boundary" => {
            vec!["--- context compacted ---".to_string()]
        }
        _ => vec![],
    }
}

/// Format an assistant message: extract text blocks and tool_use summaries.
fn format_assistant(obj: &Value) -> Vec<String> {
    let content = match obj["message"]["content"].as_array() {
        Some(arr) => arr,
        None => return vec![],
    };

    let mut lines = Vec::new();

    for block in content {
        let block_type = block["type"].as_str().unwrap_or("");
        match block_type {
            "text" => {
                if let Some(text) = block["text"].as_str() {
                    let text = text.trim();
                    if !text.is_empty() {
                        for line in text.lines() {
                            lines.push(line.to_string());
                        }
                    }
                }
            }
            "tool_use" => {
                if let Some(formatted) = format_tool_use(block) {
                    lines.push(formatted);
                }
            }
            // Skip thinking blocks silently
            _ => {}
        }
    }

    lines
}

/// Format a tool_use content block into a one-line summary.
fn format_tool_use(block: &Value) -> Option<String> {
    let name = block["name"].as_str().unwrap_or("Unknown");
    let input = &block["input"];

    let detail = match name {
        "Bash" => {
            let cmd = input["command"].as_str().unwrap_or("");
            let desc = input["description"].as_str().unwrap_or("");
            if !desc.is_empty() {
                truncate(desc, 120)
            } else {
                truncate(cmd, 120)
            }
        }
        "Read" | "NotebookRead" => {
            let path = input["file_path"].as_str().unwrap_or("");
            shorten_path(path)
        }
        "Write" | "NotebookEdit" => {
            let path = input["file_path"]
                .as_str()
                .or_else(|| input["notebook_path"].as_str())
                .unwrap_or("");
            shorten_path(path)
        }
        "Edit" => {
            let path = input["file_path"].as_str().unwrap_or("");
            shorten_path(path)
        }
        "Grep" => {
            let pattern = input["pattern"].as_str().unwrap_or("");
            let path = input["path"].as_str().unwrap_or(".");
            if path == "." {
                format!("/{pattern}/")
            } else {
                format!("/{pattern}/ in {}", shorten_path(path))
            }
        }
        "Glob" => {
            let pattern = input["pattern"].as_str().unwrap_or("");
            pattern.to_string()
        }
        "Task" => {
            let desc = input["description"].as_str().unwrap_or("");
            truncate(desc, 80)
        }
        "WebSearch" => {
            let query = input["query"].as_str().unwrap_or("");
            truncate(query, 80)
        }
        "WebFetch" => {
            let url = input["url"].as_str().unwrap_or("");
            truncate(url, 80)
        }
        "LSP" => {
            let op = input["operation"].as_str().unwrap_or("");
            let path = input["filePath"].as_str().unwrap_or("");
            format!("{op} {}", shorten_path(path))
        }
        "TodoWrite" | "TodoRead" => {
            let todos = input["todos"].as_array().map(|a| a.len()).unwrap_or(0);
            if todos > 0 {
                format!("{todos} items")
            } else {
                String::new()
            }
        }
        _ => String::new(),
    };

    if detail.is_empty() {
        Some(format!("> {name}"))
    } else {
        Some(format!("> {name}: {detail}"))
    }
}

/// Format a result event into a summary line.
fn format_result(obj: &Value) -> Vec<String> {
    let subtype = obj["subtype"].as_str().unwrap_or("unknown");

    match subtype {
        "success" => {
            let duration_ms = obj["duration_ms"].as_u64().unwrap_or(0);
            let cost = obj["total_cost_usd"].as_f64().unwrap_or(0.0);
            let input_tokens = obj["usage"]["input_tokens"].as_u64().unwrap_or(0);
            let output_tokens = obj["usage"]["output_tokens"].as_u64().unwrap_or(0);

            let duration = format_duration(duration_ms);
            vec![format!(
                "Done ({duration}, ${cost:.2}, {input_tokens}in/{output_tokens}out)"
            )]
        }
        s if s.starts_with("error") => {
            let errors = obj["errors"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join("; ")
                })
                .unwrap_or_default();
            if errors.is_empty() {
                vec![format!("Error: {subtype}")]
            } else {
                vec![format!("Error: {errors}")]
            }
        }
        _ => vec![],
    }
}

/// Format milliseconds into a human-readable duration.
fn format_duration(ms: u64) -> String {
    let secs = ms / 1000;
    if secs < 60 {
        format!("{secs}s")
    } else {
        let mins = secs / 60;
        let rem = secs % 60;
        format!("{mins}m {rem}s")
    }
}

/// Truncate a string to `max` characters, appending "..." if truncated.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max.min(s.len())])
    }
}

/// Shorten a file path by keeping only the last two components.
fn shorten_path(path: &str) -> String {
    let parts: Vec<&str> = path.rsplitn(3, '/').collect();
    match parts.len() {
        0 => path.to_string(),
        1 => parts[0].to_string(),
        2 => format!("{}/{}", parts[1], parts[0]),
        _ => format!(".../{}/{}", parts[1], parts[0]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input() {
        assert!(format_ndjson_line("").is_empty());
        assert!(format_ndjson_line("  ").is_empty());
    }

    #[test]
    fn invalid_json_passes_through() {
        let result = format_ndjson_line("not json at all");
        assert_eq!(result, vec!["not json at all"]);
    }

    #[test]
    fn system_init() {
        let json = r#"{"type":"system","subtype":"init","model":"claude-sonnet-4-5-20250929","cwd":"/home/user/project","session_id":"abc","uuid":"def","tools":[]}"#;
        let result = format_ndjson_line(json);
        assert_eq!(result.len(), 1);
        assert!(result[0].contains("Session started"));
        assert!(result[0].contains("claude-sonnet"));
    }

    #[test]
    fn system_compact_boundary() {
        let json =
            r#"{"type":"system","subtype":"compact_boundary","uuid":"a","session_id":"b"}"#;
        let result = format_ndjson_line(json);
        assert_eq!(result, vec!["--- context compacted ---"]);
    }

    #[test]
    fn assistant_text() {
        let json = r#"{"type":"assistant","message":{"content":[{"type":"text","text":"Hello, world!"}]}}"#;
        let result = format_ndjson_line(json);
        assert_eq!(result, vec!["Hello, world!"]);
    }

    #[test]
    fn assistant_multiline_text() {
        let json = r#"{"type":"assistant","message":{"content":[{"type":"text","text":"line 1\nline 2\nline 3"}]}}"#;
        let result = format_ndjson_line(json);
        assert_eq!(result, vec!["line 1", "line 2", "line 3"]);
    }

    #[test]
    fn assistant_tool_use_bash() {
        let json = r#"{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash","id":"t1","input":{"command":"ls -la","description":"List files"}}]}}"#;
        let result = format_ndjson_line(json);
        assert_eq!(result, vec!["> Bash: List files"]);
    }

    #[test]
    fn assistant_tool_use_bash_no_desc() {
        let json = r#"{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash","id":"t1","input":{"command":"cargo test"}}]}}"#;
        let result = format_ndjson_line(json);
        assert_eq!(result, vec!["> Bash: cargo test"]);
    }

    #[test]
    fn assistant_tool_use_read() {
        let json = r#"{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Read","id":"t1","input":{"file_path":"/home/user/project/src/main.rs"}}]}}"#;
        let result = format_ndjson_line(json);
        assert_eq!(result, vec!["> Read: .../src/main.rs"]);
    }

    #[test]
    fn assistant_tool_use_edit() {
        let json = r#"{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Edit","id":"t1","input":{"file_path":"/foo/bar.rs","old_string":"a","new_string":"b"}}]}}"#;
        let result = format_ndjson_line(json);
        assert_eq!(result, vec!["> Edit: .../foo/bar.rs"]);
    }

    #[test]
    fn assistant_tool_use_grep() {
        let json = r#"{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Grep","id":"t1","input":{"pattern":"fn main","path":"/src"}}]}}"#;
        let result = format_ndjson_line(json);
        assert_eq!(result, vec!["> Grep: /fn main/ in /src"]);
    }

    #[test]
    fn assistant_mixed_content() {
        let json = r#"{"type":"assistant","message":{"content":[{"type":"text","text":"Let me check."},{"type":"tool_use","name":"Read","id":"t1","input":{"file_path":"src/lib.rs"}}]}}"#;
        let result = format_ndjson_line(json);
        assert_eq!(result, vec!["Let me check.", "> Read: src/lib.rs"]);
    }

    #[test]
    fn user_message_skipped() {
        let json = r#"{"type":"user","message":{"role":"user","content":"test"}}"#;
        assert!(format_ndjson_line(json).is_empty());
    }

    #[test]
    fn thinking_block_skipped() {
        let json = r#"{"type":"assistant","message":{"content":[{"type":"thinking","thinking":"deep thoughts"}]}}"#;
        assert!(format_ndjson_line(json).is_empty());
    }

    #[test]
    fn result_success() {
        let json = r#"{"type":"result","subtype":"success","duration_ms":45000,"total_cost_usd":0.15,"usage":{"input_tokens":5000,"output_tokens":1200}}"#;
        let result = format_ndjson_line(json);
        assert_eq!(result.len(), 1);
        assert!(result[0].contains("Done"));
        assert!(result[0].contains("45s"));
        assert!(result[0].contains("$0.15"));
    }

    #[test]
    fn result_success_minutes() {
        let json = r#"{"type":"result","subtype":"success","duration_ms":125000,"total_cost_usd":1.23,"usage":{"input_tokens":50000,"output_tokens":12000}}"#;
        let result = format_ndjson_line(json);
        assert!(result[0].contains("2m 5s"));
    }

    #[test]
    fn result_error() {
        let json =
            r#"{"type":"result","subtype":"error_max_turns","errors":["exceeded maximum turns"]}"#;
        let result = format_ndjson_line(json);
        assert_eq!(result, vec!["Error: exceeded maximum turns"]);
    }

    #[test]
    fn shorten_path_short() {
        assert_eq!(shorten_path("lib.rs"), "lib.rs");
    }

    #[test]
    fn shorten_path_two_components() {
        assert_eq!(shorten_path("src/lib.rs"), "src/lib.rs");
    }

    #[test]
    fn shorten_path_long() {
        assert_eq!(
            shorten_path("/home/user/project/src/lib.rs"),
            ".../src/lib.rs"
        );
    }

    #[test]
    fn truncate_short() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn truncate_long() {
        assert_eq!(truncate("hello world!", 5), "hello...");
    }

    #[test]
    fn format_duration_seconds() {
        assert_eq!(format_duration(5000), "5s");
    }

    #[test]
    fn format_duration_minutes() {
        assert_eq!(format_duration(125000), "2m 5s");
    }

    #[test]
    fn unknown_tool() {
        let json = r#"{"type":"assistant","message":{"content":[{"type":"tool_use","name":"CustomTool","id":"t1","input":{}}]}}"#;
        let result = format_ndjson_line(json);
        assert_eq!(result, vec!["> CustomTool"]);
    }
}
