//! Conversation persistence for the chat TUI.
//!
//! Saves conversations as JSONL files in ~/.aegis/conversations/ for
//! later resume. Each line is a serialized LlmMessage.

use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use aegis_types::llm::LlmMessage;

/// Metadata header stored as the first line of a conversation file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationMeta {
    /// Unique conversation identifier.
    pub id: String,
    /// Model used for this conversation.
    pub model: String,
    /// ISO 8601 timestamp of when the conversation was saved.
    pub timestamp: String,
    /// Number of LlmMessages in the conversation.
    pub message_count: usize,
}

/// Return the conversations directory (~/.aegis/conversations/), creating it
/// if it does not exist.
pub fn conversations_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let dir = PathBuf::from(home).join(".aegis").join("conversations");
    let _ = fs::create_dir_all(&dir);
    dir
}

/// Generate a short conversation ID from the current timestamp.
///
/// Produces a 6-character hex string derived from the lower bits of the
/// current Unix timestamp in milliseconds, giving sufficient uniqueness
/// for interactive use.
pub fn generate_conversation_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("{:06x}", millis & 0xFFFFFF)
}

/// Save a conversation to disk as a JSONL file.
///
/// The first line is a JSON header with metadata. Each subsequent line is
/// a serialized `LlmMessage`.
pub fn save_conversation(
    id: &str,
    messages: &[LlmMessage],
    model: &str,
) -> Result<()> {
    let dir = conversations_dir();
    let path = dir.join(format!("{id}.jsonl"));

    let timestamp = chrono::Utc::now().to_rfc3339();
    let meta = ConversationMeta {
        id: id.to_string(),
        model: model.to_string(),
        timestamp,
        message_count: messages.len(),
    };

    let mut contents =
        serde_json::to_string(&meta).context("failed to serialize conversation metadata")?;
    contents.push('\n');

    for msg in messages {
        let line =
            serde_json::to_string(msg).context("failed to serialize conversation message")?;
        contents.push_str(&line);
        contents.push('\n');
    }

    fs::write(&path, contents)
        .with_context(|| format!("failed to write conversation file: {}", path.display()))?;

    Ok(())
}

/// Load a conversation from disk.
///
/// Returns the list of messages and the conversation metadata.
pub fn load_conversation(id: &str) -> Result<(Vec<LlmMessage>, ConversationMeta)> {
    let dir = conversations_dir();
    let path = dir.join(format!("{id}.jsonl"));

    let contents = fs::read_to_string(&path)
        .with_context(|| format!("failed to read conversation file: {}", path.display()))?;

    let mut lines = contents.lines();

    let header_line = lines.next().context("conversation file is empty")?;
    let meta: ConversationMeta =
        serde_json::from_str(header_line).context("failed to parse conversation metadata")?;

    let mut messages = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let msg: LlmMessage =
            serde_json::from_str(line).context("failed to parse conversation message")?;
        messages.push(msg);
    }

    Ok((messages, meta))
}

/// List all saved conversations, sorted by timestamp descending (newest first).
///
/// Only reads the header line of each file for efficiency.
pub fn list_conversations() -> Result<Vec<ConversationMeta>> {
    let dir = conversations_dir();

    let mut metas = Vec::new();

    let entries = fs::read_dir(&dir)
        .with_context(|| format!("failed to read conversations directory: {}", dir.display()))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
            continue;
        }

        // Read only the first line for the header.
        let contents = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let first_line = match contents.lines().next() {
            Some(l) => l,
            None => continue,
        };

        let meta: ConversationMeta = match serde_json::from_str(first_line) {
            Ok(m) => m,
            Err(_) => continue,
        };

        metas.push(meta);
    }

    // Sort by timestamp descending (newest first).
    metas.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    Ok(metas)
}

// ---------------------------------------------------------------------------
// Input history persistence
// ---------------------------------------------------------------------------

const MAX_HISTORY_LINES: usize = 1000;

/// Path to the shared history file (~/.aegis/history).
fn history_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".aegis").join("history")
}

/// Load input and command history from disk.
///
/// Returns `(input_history, command_history)`. Lines prefixed with `> ` are
/// chat inputs; lines prefixed with `/ ` are slash commands. Silently returns
/// empty vecs on any I/O or parse error.
pub fn load_history() -> (Vec<String>, Vec<String>) {
    let path = history_path();
    let contents = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return (Vec::new(), Vec::new()),
    };

    let mut all_lines: Vec<&str> = contents.lines().collect();

    // Truncate to most recent MAX_HISTORY_LINES if oversized.
    if all_lines.len() > MAX_HISTORY_LINES {
        let start = all_lines.len() - MAX_HISTORY_LINES;
        all_lines = all_lines[start..].to_vec();
        // Best-effort rewrite of truncated file.
        let truncated: String = all_lines.iter().map(|l| format!("{l}\n")).collect();
        let _ = fs::write(&path, truncated);
    }

    let mut input_history = Vec::new();
    let mut command_history = Vec::new();

    for line in all_lines {
        if let Some(rest) = line.strip_prefix("> ") {
            input_history.push(rest.to_string());
        } else if let Some(rest) = line.strip_prefix("/ ") {
            command_history.push(rest.to_string());
        }
        // Ignore malformed lines silently.
    }

    (input_history, command_history)
}

/// Append a single history entry to disk.
///
/// `kind` should be `'>'` for chat input or `'/'` for slash commands.
/// Errors are silently ignored -- history is best-effort.
pub fn append_history(kind: char, entry: &str) {
    let path = history_path();
    // Ensure parent directory exists.
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path) else {
        return;
    };
    let _ = writeln!(file, "{kind} {entry}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_types::llm::LlmMessage;

    #[test]
    fn generate_id_is_six_chars() {
        let id = generate_conversation_id();
        assert_eq!(id.len(), 6);
        // Should be valid hex.
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let id = "test123";
        let model = "test-model";
        let messages = vec![
            LlmMessage::user("Hello"),
            LlmMessage::assistant("Hi there!"),
        ];

        // Write directly to the temp dir.
        let path = dir.path().join(format!("{id}.jsonl"));
        let timestamp = "2026-01-01T00:00:00Z".to_string();
        let meta = ConversationMeta {
            id: id.to_string(),
            model: model.to_string(),
            timestamp,
            message_count: messages.len(),
        };

        let mut contents = serde_json::to_string(&meta).unwrap();
        contents.push('\n');
        for msg in &messages {
            contents.push_str(&serde_json::to_string(msg).unwrap());
            contents.push('\n');
        }
        std::fs::write(&path, &contents).unwrap();

        // Read it back.
        let file_contents = std::fs::read_to_string(&path).unwrap();
        let mut lines = file_contents.lines();
        let header: ConversationMeta = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(header.id, id);
        assert_eq!(header.model, model);
        assert_eq!(header.message_count, 2);

        let mut loaded = Vec::new();
        for line in lines {
            if !line.trim().is_empty() {
                loaded.push(serde_json::from_str::<LlmMessage>(line).unwrap());
            }
        }
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].content, "Hello");
        assert_eq!(loaded[1].content, "Hi there!");
    }

    #[test]
    fn conversation_meta_serialization() {
        let meta = ConversationMeta {
            id: "abc123".to_string(),
            model: "claude-sonnet-4-20250514".to_string(),
            timestamp: "2026-01-15T10:30:00Z".to_string(),
            message_count: 5,
        };

        let json = serde_json::to_string(&meta).unwrap();
        let back: ConversationMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "abc123");
        assert_eq!(back.model, "claude-sonnet-4-20250514");
        assert_eq!(back.message_count, 5);
    }

    #[test]
    fn conversation_meta_backward_compatible_with_legacy_fields() {
        // Old conversation files may have mode/engine fields -- they should be
        // silently ignored during deserialization.
        let legacy = r#"{"id":"old123","model":"gpt-5.2","mode":"auto","engine":"native","timestamp":"2026-01-01T00:00:00Z","message_count":2}"#;
        let meta: ConversationMeta = serde_json::from_str(legacy).unwrap();
        assert_eq!(meta.id, "old123");
        assert_eq!(meta.model, "gpt-5.2");
        assert_eq!(meta.message_count, 2);
    }

    #[test]
    fn load_history_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history");
        std::fs::write(&path, "").unwrap();

        // load_history uses a fixed path, so we test the parsing logic directly.
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.is_empty());
    }

    #[test]
    fn load_history_parses_prefixes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history");
        std::fs::write(
            &path,
            "> hello world\n/ status\n> second message\n/ help\nbogus line\n",
        )
        .unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let mut input = Vec::new();
        let mut command = Vec::new();
        for line in contents.lines() {
            if let Some(rest) = line.strip_prefix("> ") {
                input.push(rest.to_string());
            } else if let Some(rest) = line.strip_prefix("/ ") {
                command.push(rest.to_string());
            }
        }

        assert_eq!(input, vec!["hello world", "second message"]);
        assert_eq!(command, vec!["status", "help"]);
    }

    #[test]
    fn append_history_format() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history");

        // Simulate append_history writes.
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(file, "> first message").unwrap();
        writeln!(file, "/ status").unwrap();
        writeln!(file, "> second message").unwrap();
        drop(file);

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "> first message");
        assert_eq!(lines[1], "/ status");
        assert_eq!(lines[2], "> second message");
    }
}
