//! Channel (Telegram) conversation persistence, heartbeat helpers,
//! system prompt construction, and skill manifest parsing.

// ---------------------------------------------------------------------------
// System prompt
// ---------------------------------------------------------------------------

/// Build a system prompt for channel (Telegram) chat.
///
/// Loads the same workspace context files as the TUI's system prompt
/// (SOUL.md, IDENTITY.md, USER.md, MEMORY.md, HEARTBEAT.md) but tailored
/// for Telegram's constraints (concise responses, plain text).
pub(crate) fn build_channel_system_prompt() -> String {
    use std::fmt::Write;

    let ws = aegis_types::daemon::workspace_dir();
    let max_file_chars: usize = 8000;

    let mut prompt = String::with_capacity(8192);

    // Core identity and behaviour
    prompt.push_str(
        "You are an autonomous agent chatting via Telegram. Keep responses concise \
         (under 2000 chars). Use plain text, no markdown formatting.\n\n\
         You have FULL access to the user's computer through your tools: bash, \
         read_file, write_file, edit_file, glob_search, grep_search. When the user \
         asks you to DO something -- record audio, take notes, search files, run \
         commands, manage tasks -- use your tools to actually do it. Do not describe \
         what you would do or say you can't. Check what's available and make it happen.\n\n",
    );

    // Discover installed skills from ~/.aegis/skills/
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let skills_dir = std::path::PathBuf::from(&home)
        .join(".aegis")
        .join("skills");

    let mut skills: Vec<(String, String, Vec<String>)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&skills_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let manifest_path = path.join("manifest.toml");
            if let Ok(manifest) = std::fs::read_to_string(&manifest_path) {
                let desc = parse_manifest_field(&manifest, "description").unwrap_or_default();
                let entry_point = parse_manifest_field(&manifest, "entry_point")
                    .unwrap_or_else(|| "run.sh".to_string());
                let commands = parse_manifest_commands(&manifest);
                let invoke_path = path.join(&entry_point);
                let mut skill_lines = vec![format!(
                    "- {name}: {desc}\n  Path: {}",
                    invoke_path.display()
                )];
                if !commands.is_empty() {
                    for cmd in &commands {
                        skill_lines.push(format!("  {cmd}"));
                    }
                }
                skills.push((name, skill_lines.join("\n"), commands));
            }
        }
    }
    skills.sort_by(|a, b| a.0.cmp(&b.0));

    if !skills.is_empty() {
        prompt.push_str("# Installed Skills\n\n");
        prompt.push_str(
            "Skills are shell scripts. Invoke via bash with JSON on stdin:\n\
             echo '{\"parameters\":{\"args\":[\"ARG1\",\"ARG2\"]}}' | SCRIPT_PATH\n\n",
        );
        for (_, desc, _) in &skills {
            prompt.push_str(desc);
            prompt.push('\n');
        }
        prompt.push('\n');
    }

    // Check for useful CLI tools
    let mut available_tools = Vec::new();
    for tool in &["ffmpeg", "whisper", "sox", "say", "pandoc", "jq"] {
        if std::process::Command::new("which")
            .arg(tool)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            available_tools.push(*tool);
        }
    }
    if !available_tools.is_empty() {
        let _ = writeln!(
            prompt,
            "Available CLI tools: {}\n",
            available_tools.join(", ")
        );
    }

    // Load workspace context files (same set as the TUI's system_prompt.rs)
    let files: &[(&str, &str)] = &[
        ("SOUL.md", "Soul"),
        ("IDENTITY.md", "Identity"),
        ("USER.md", "User"),
        ("MEMORY.md", "Memory"),
        ("HEARTBEAT.md", "Heartbeat"),
    ];

    let mut has_soul = false;
    let mut has_memory = false;

    for &(filename, label) in files {
        let path = ws.join(filename);
        if let Ok(contents) = std::fs::read_to_string(&path) {
            let trimmed = contents.trim();
            if trimmed.is_empty() {
                continue;
            }
            if filename == "SOUL.md" {
                has_soul = true;
            }
            if filename == "MEMORY.md" {
                has_memory = true;
            }
            let content = if contents.len() > max_file_chars {
                format!("{}...[truncated]", &contents[..max_file_chars])
            } else {
                contents
            };
            let _ = writeln!(prompt, "# {label}\n\n{content}\n");
        }
    }

    // Context-file instructions (matches TUI behaviour)
    if has_soul {
        prompt.push_str(
            "Embody the persona and tone from SOUL.md above. \
             Avoid stiff, generic replies.\n\n",
        );
    }
    if has_memory {
        prompt.push_str(
            "MEMORY.md contains your persistent notes from prior sessions. \
             Reference it for context.\n\n",
        );
    }

    prompt
}

// ---------------------------------------------------------------------------
// Skill manifest parsing
// ---------------------------------------------------------------------------

/// Parse a simple `key = "value"` field from a TOML manifest string.
pub(crate) fn parse_manifest_field(manifest: &str, key: &str) -> Option<String> {
    for line in manifest.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(key) {
            let rest = rest.trim_start();
            if let Some(rest) = rest.strip_prefix('=') {
                let val = rest.trim().trim_matches('"').trim_matches('\'').trim();
                if !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

/// Parse `[[commands]]` entries from a skill manifest, returning usage strings.
pub(crate) fn parse_manifest_commands(manifest: &str) -> Vec<String> {
    let mut commands = Vec::new();
    let mut in_command = false;
    let mut current_usage: Option<String> = None;
    let mut current_desc: Option<String> = None;

    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed == "[[commands]]" {
            // Flush previous command
            if let Some(usage) = current_usage.take() {
                let desc = current_desc.take().unwrap_or_default();
                if desc.is_empty() {
                    commands.push(format!("Command: {usage}"));
                } else {
                    commands.push(format!("Command: {usage} -- {desc}"));
                }
            }
            in_command = true;
            continue;
        }
        if in_command {
            if trimmed.starts_with('[') && trimmed != "[[commands]]" {
                // New section, flush
                if let Some(usage) = current_usage.take() {
                    let desc = current_desc.take().unwrap_or_default();
                    if desc.is_empty() {
                        commands.push(format!("Command: {usage}"));
                    } else {
                        commands.push(format!("Command: {usage} -- {desc}"));
                    }
                }
                in_command = false;
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix("usage") {
                let rest = rest.trim_start();
                if let Some(rest) = rest.strip_prefix('=') {
                    current_usage =
                        Some(rest.trim().trim_matches('"').trim_matches('\'').to_string());
                }
            }
            if let Some(rest) = trimmed.strip_prefix("description") {
                let rest = rest.trim_start();
                if let Some(rest) = rest.strip_prefix('=') {
                    current_desc =
                        Some(rest.trim().trim_matches('"').trim_matches('\'').to_string());
                }
            }
        }
    }
    // Flush last command
    if let Some(usage) = current_usage {
        let desc = current_desc.unwrap_or_default();
        if desc.is_empty() {
            commands.push(format!("Command: {usage}"));
        } else {
            commands.push(format!("Command: {usage} -- {desc}"));
        }
    }
    commands
}

// ---------------------------------------------------------------------------
// Conversation persistence
// ---------------------------------------------------------------------------

/// Metadata header stored as the first line of a conversation JSONL file.
/// Mirrors `ConversationMeta` in `aegis-cli/src/chat_tui/persistence.rs`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct ChannelConversationMeta {
    pub id: String,
    pub model: String,
    pub timestamp: String,
    pub message_count: usize,
}

/// Return the conversations directory (`~/.aegis/conversations/`), creating it
/// if it does not exist.
pub(crate) fn channel_conversations_dir() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let dir = std::path::PathBuf::from(home)
        .join(".aegis")
        .join("conversations");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// Generate a short conversation ID from the current timestamp (6-char hex).
pub(crate) fn channel_generate_conversation_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("{:06x}", millis & 0xFFFFFF)
}

/// Save a conversation to disk as a JSONL file (same format as TUI persistence).
pub(crate) fn channel_save_conversation(
    id: &str,
    messages: &[aegis_types::llm::LlmMessage],
    model: &str,
) {
    let dir = channel_conversations_dir();
    let path = dir.join(format!("{id}.jsonl"));

    let timestamp = chrono::Utc::now().to_rfc3339();
    let meta = ChannelConversationMeta {
        id: id.to_string(),
        model: model.to_string(),
        timestamp,
        message_count: messages.len(),
    };

    let mut contents = match serde_json::to_string(&meta) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "failed to serialize conversation metadata");
            return;
        }
    };
    contents.push('\n');

    for msg in messages {
        match serde_json::to_string(msg) {
            Ok(line) => {
                contents.push_str(&line);
                contents.push('\n');
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to serialize conversation message");
            }
        }
    }

    if let Err(e) = std::fs::write(&path, contents) {
        tracing::warn!(error = %e, path = %path.display(), "failed to write conversation file");
    }
}

/// Load a conversation from disk by ID.
pub(crate) fn channel_load_conversation(
    id: &str,
) -> Option<(Vec<aegis_types::llm::LlmMessage>, ChannelConversationMeta)> {
    let dir = channel_conversations_dir();
    let path = dir.join(format!("{id}.jsonl"));

    let contents = std::fs::read_to_string(&path).ok()?;
    let mut lines = contents.lines();

    let header_line = lines.next()?;
    let meta: ChannelConversationMeta = serde_json::from_str(header_line).ok()?;

    let mut messages = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(msg) = serde_json::from_str::<aegis_types::llm::LlmMessage>(line) {
            messages.push(msg);
        }
    }

    Some((messages, meta))
}

/// List all saved conversations, newest first (reads only header lines).
pub(crate) fn channel_list_conversations() -> Vec<ChannelConversationMeta> {
    let dir = channel_conversations_dir();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut metas = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
            continue;
        }
        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let first_line = match contents.lines().next() {
            Some(l) => l,
            None => continue,
        };
        if let Ok(meta) = serde_json::from_str::<ChannelConversationMeta>(first_line) {
            metas.push(meta);
        }
    }

    metas.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    metas
}

// ---------------------------------------------------------------------------
// Heartbeat helpers
// ---------------------------------------------------------------------------

/// Check if HEARTBEAT.md content has actionable items (not just template boilerplate).
///
/// Ported from TUI's `ChatApp::is_heartbeat_content_actionable()`. Returns true
/// only if at least one line contains non-boilerplate content.
pub(crate) fn is_heartbeat_content_actionable(content: &str) -> bool {
    for line in content.lines() {
        let trimmed = line.trim();
        // Skip empty, headers, horizontal rules, fenced code markers.
        if trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed.starts_with("---")
            || trimmed.starts_with("```")
        {
            continue;
        }
        // Skip markdown emphasis-only lines (e.g. _Things to check..._)
        if trimmed.starts_with('_') && trimmed.ends_with('_') {
            continue;
        }
        // Skip known template boilerplate.
        let lower = trimmed.to_lowercase();
        if lower.contains("what goes here")
            || lower.contains("update this file")
            || lower.contains("keep this file empty")
            || lower.contains("persists across sessions")
            || lower.starts_with("if nothing needs attention")
            || lower.contains("heartbeat_ok")
        {
            continue;
        }
        // Skip generic list items without checkboxes.
        if lower.starts_with("- ")
            && !lower.contains("- [ ]")
            && !lower.contains("- [x]")
            && (lower.contains("recurring checks")
                || lower.contains("monitoring")
                || lower.contains("build status")
                || lower.contains("files or configs")
                || lower.contains("reminders about")
                || lower.contains("time-sensitive"))
        {
            continue;
        }
        // Found a non-boilerplate, non-empty line.
        return true;
    }
    false
}

/// Check if a heartbeat LLM response is effectively empty (HEARTBEAT_OK or trivial).
///
/// Strips HEARTBEAT_OK token variants and returns true if the remaining text
/// is shorter than `ack_max_chars`.
pub(crate) fn is_heartbeat_response_empty(content: &str, ack_max_chars: usize) -> bool {
    let text = content.trim();
    if text.is_empty() {
        return true;
    }
    let stripped = text
        .replace("HEARTBEAT_OK", "")
        .replace("heartbeat_ok", "")
        .replace("Heartbeat_OK", "")
        .replace("HEARTBEAT_OK.", "")
        .trim()
        .to_string();
    stripped.len() < ack_max_chars
}

// ---------------------------------------------------------------------------
// Model detection
// ---------------------------------------------------------------------------

/// Detect the LLM model to use for channel operations (chat, heartbeat).
///
/// Checks the credential store for a configured model, then falls back to
/// the first available provider's default model.
pub(crate) fn detect_channel_model() -> String {
    let store = aegis_types::credentials::CredentialStore::load_default().unwrap_or_default();
    let mut found = None;
    for detected in aegis_types::providers::scan_providers() {
        if detected.available {
            if let Some(cred) = store.get(detected.info.id) {
                if let Some(ref m) = cred.model {
                    found = Some(m.clone());
                    break;
                }
            }
        }
    }
    found
        .or_else(|| {
            aegis_types::providers::scan_providers()
                .into_iter()
                .find(|d| d.available && !d.info.default_model.is_empty())
                .map(|d| d.info.default_model.to_string())
        })
        .unwrap_or_else(|| "claude-sonnet-4-20250514".to_string())
}
