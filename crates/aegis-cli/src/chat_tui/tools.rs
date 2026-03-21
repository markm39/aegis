//! Tool definitions, schemas, input summarization, and skill infrastructure
//! for the chat TUI's agentic loop.

use super::system_prompt::ToolDescription;

/// Skill command prompts, embedded at compile time from prompts/skills/.
pub mod skill_prompts {
    pub const DEBUG: &str = include_str!("prompts/skills/debug.md");
    pub const DOC: &str = include_str!("prompts/skills/doc.md");
    pub const EXPLAIN: &str = include_str!("prompts/skills/explain.md");
    pub const REFACTOR: &str = include_str!("prompts/skills/refactor.md");
    pub const TEST: &str = include_str!("prompts/skills/test.md");
    pub const REVIEW: &str = include_str!("prompts/skills/review.md");
    pub const SECURITY: &str = include_str!("prompts/skills/security.md");
    pub const PERF: &str = include_str!("prompts/skills/perf.md");
    pub const PANEL_REVIEW: &str = include_str!("prompts/skills/panel_review.md");
    pub const LINK_WORKTREE: &str = include_str!("prompts/skills/link_worktree.md");
}

/// A slash command backed by a prompt template.
pub struct SkillCommand {
    /// Command name (what the user types after `/`).
    pub name: &'static str,
    /// Prompt template with `$ARGUMENTS` placeholder.
    pub prompt: &'static str,
    /// Whether the command requires an argument.
    pub needs_arg: bool,
    /// Usage hint shown when a required arg is missing.
    pub arg_hint: &'static str,
}

/// All available skill commands. Looked up in `execute_command()`.
pub const SKILL_COMMANDS: &[SkillCommand] = &[
    SkillCommand {
        name: "debug",
        prompt: skill_prompts::DEBUG,
        needs_arg: true,
        arg_hint: "Usage: /debug <error message or description>",
    },
    SkillCommand {
        name: "doc",
        prompt: skill_prompts::DOC,
        needs_arg: true,
        arg_hint: "Usage: /doc <file or area>",
    },
    SkillCommand {
        name: "explain",
        prompt: skill_prompts::EXPLAIN,
        needs_arg: true,
        arg_hint: "Usage: /explain <file, function, or concept>",
    },
    SkillCommand {
        name: "refactor",
        prompt: skill_prompts::REFACTOR,
        needs_arg: true,
        arg_hint: "Usage: /refactor <file or area>",
    },
    SkillCommand {
        name: "test",
        prompt: skill_prompts::TEST,
        needs_arg: true,
        arg_hint: "Usage: /test <file or function>",
    },
    SkillCommand {
        name: "review",
        prompt: skill_prompts::REVIEW,
        needs_arg: false,
        arg_hint: "Usage: /review [file or description]",
    },
    SkillCommand {
        name: "security",
        prompt: skill_prompts::SECURITY,
        needs_arg: true,
        arg_hint: "Usage: /security <file or area>",
    },
    SkillCommand {
        name: "perf",
        prompt: skill_prompts::PERF,
        needs_arg: true,
        arg_hint: "Usage: /perf <file or area>",
    },
    SkillCommand {
        name: "panel-review",
        prompt: skill_prompts::PANEL_REVIEW,
        needs_arg: true,
        arg_hint: "Usage: /panel-review <topic or question>",
    },
    SkillCommand {
        name: "link-worktree",
        prompt: skill_prompts::LINK_WORKTREE,
        needs_arg: true,
        arg_hint: "Usage: /link-worktree <worktree-path>",
    },
];

/// Result of a skill execution dispatched to a background thread.
pub struct SkillExecResult {
    /// The slash command that triggered this skill.
    pub command_name: String,
    /// The skill output, or an error message.
    pub output: anyhow::Result<aegis_skills::SkillOutput, String>,
}

/// Discover skills and build a registry + command router.
///
/// Scans both the bundled `skills/` directory and user-installed skills in
/// `~/.aegis/skills/` for skill manifests, advances each through the
/// lifecycle (discover -> validate -> load -> activate), and builds a
/// `CommandRouter` from their `[[commands]]` sections.
///
/// User-installed skills take precedence over bundled skills with the same
/// name (the bundled duplicate is skipped).
///
/// Returns empty registry/router if no skills are found.
pub fn init_skills() -> (aegis_skills::SkillRegistry, aegis_skills::CommandRouter) {
    let mut registry = aegis_skills::SkillRegistry::new();
    let mut router = aegis_skills::CommandRouter::new();

    // Collect all skill instances: user-installed first (so they take
    // precedence), then bundled skills as fallback.
    let mut all_instances = Vec::new();
    let mut seen_names = std::collections::HashSet::new();

    // 1. User-installed skills from ~/.aegis/skills/.
    if let Ok(home) = std::env::var("HOME") {
        let user_skills_dir = std::path::PathBuf::from(home).join(".aegis/skills");
        if user_skills_dir.is_dir() {
            if let Ok(instances) = aegis_skills::discover_skills(&user_skills_dir) {
                for instance in instances {
                    seen_names.insert(instance.manifest.name.clone());
                    all_instances.push(instance);
                }
            }
        }
    }

    // 2. Bundled skills (skip any already found in user dir).
    for instance in aegis_skills::discover_bundled_skills().unwrap_or_default() {
        if seen_names.contains(&instance.manifest.name) {
            continue;
        }
        all_instances.push(instance);
    }

    for mut instance in all_instances {
        // Best-effort lifecycle advancement: validate -> load -> activate.
        if instance.validate().is_err() {
            continue;
        }
        if instance.load().is_err() {
            continue;
        }
        if instance.activate().is_err() {
            continue;
        }
        let _ = registry.register(instance);
    }

    aegis_skills::auto_register_commands(&mut router, &registry);

    (registry, router)
}

/// Get tool descriptions for the system prompt.
///
/// Returns builtin tool descriptions plus dynamically generated `skill_*`
/// tool definitions for each installed skill's commands. The `skill_` prefix
/// makes routing trivial in the agent loop.
pub fn get_tool_descriptions(skills: &aegis_skills::SkillRegistry) -> Vec<ToolDescription> {
    let mut descs = vec![
        ToolDescription {
            name: "bash".into(),
            description: "Run shell commands for builds, tests, git, and system administration. \
                          For capabilities covered by installed skills (audio, search, messaging, etc.), \
                          use the dedicated skill_* tools instead -- they provide structured output, \
                          subprocess isolation, and policy enforcement. Do not use bash to access \
                          credential files or inject input directly."
                .into(),
        },
        ToolDescription {
            name: "read_file".into(),
            description: "Read file contents from disk (max 500KB)".into(),
        },
        ToolDescription {
            name: "write_file".into(),
            description: "Create new files or fully replace file contents. For modifying existing \
                          files, prefer apply_patch."
                .into(),
        },
        ToolDescription {
            name: "edit_file".into(),
            description: "Replace the first occurrence of old_string with new_string in a file"
                .into(),
        },
        ToolDescription {
            name: "glob_search".into(),
            description: "Find files matching a glob pattern".into(),
        },
        ToolDescription {
            name: "grep_search".into(),
            description: "Search file contents for a regex pattern".into(),
        },
        ToolDescription {
            name: "apply_patch".into(),
            description: "Edit existing files using V4A patches. Preferred over write_file for \
                          modifications. See apply_patch instructions section for the required format."
                .into(),
        },
        ToolDescription {
            name: "file_search".into(),
            description: "Fuzzy search for files by name across the project. Respects .gitignore. \
                          Returns ranked matches with relevance scores."
                .into(),
        },
        ToolDescription {
            name: "task".into(),
            description: "Spawn a coding subagent (full agent instance with bash + file tools). \
                          Use for complex multi-step work, audio processing, data pipelines, etc. \
                          Returns a summary when done. Use run_in_background for concurrent tasks."
                .into(),
        },
    ];

    // Add skill_* tool definitions from the skill registry.
    for instance in skills.list() {
        if let Some(commands) = &instance.manifest.commands {
            for cmd in commands {
                let tool_name = format!("skill_{}", cmd.name);
                let desc = if cmd.description.is_empty() {
                    format!(
                        "Skill: {} ({}). Usage: {}",
                        instance.manifest.name, instance.manifest.description, cmd.usage,
                    )
                } else {
                    format!("{}. Usage: {}", cmd.description, cmd.usage,)
                };
                descs.push(ToolDescription {
                    name: tool_name,
                    description: desc,
                });
            }
        }
    }

    descs
}

/// Get the JSON Schema for a tool by name.
pub fn tool_schema_for(name: &str) -> serde_json::Value {
    match name {
        "bash" => serde_json::json!({
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The shell command to execute"
                }
            },
            "required": ["command"]
        }),
        "read_file" => serde_json::json!({
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Absolute path to the file to read"
                }
            },
            "required": ["file_path"]
        }),
        "write_file" => serde_json::json!({
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Absolute path to the file to write"
                },
                "content": {
                    "type": "string",
                    "description": "Content to write to the file"
                }
            },
            "required": ["file_path", "content"]
        }),
        "edit_file" => serde_json::json!({
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Absolute path to the file to edit"
                },
                "old_string": {
                    "type": "string",
                    "description": "The exact string to find and replace"
                },
                "new_string": {
                    "type": "string",
                    "description": "The replacement string"
                }
            },
            "required": ["file_path", "old_string", "new_string"]
        }),
        "glob_search" => serde_json::json!({
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Glob pattern to match files (e.g., \"**/*.rs\")"
                },
                "path": {
                    "type": "string",
                    "description": "Base directory to search in (defaults to current directory)"
                }
            },
            "required": ["pattern"]
        }),
        "grep_search" => serde_json::json!({
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Regular expression pattern to search for"
                },
                "path": {
                    "type": "string",
                    "description": "Directory or file to search in (defaults to current directory)"
                },
                "include": {
                    "type": "string",
                    "description": "Glob pattern to filter files (e.g., \"*.rs\")"
                }
            },
            "required": ["pattern"]
        }),
        "apply_patch" => serde_json::json!({
            "type": "object",
            "properties": {
                "patch": {
                    "type": "string",
                    "description": "V4A patch content. Must start with '*** Begin Patch' and end with '*** End Patch'.\nExample:\n*** Begin Patch\n*** Update File: src/main.rs\n@@ fn main():\n- old_line\n+ new_line\n*** End Patch"
                }
            },
            "required": ["patch"]
        }),
        "file_search" => serde_json::json!({
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Fuzzy search query for file names"
                },
                "path": {
                    "type": "string",
                    "description": "Directory to search in (defaults to current directory)"
                }
            },
            "required": ["query"]
        }),
        "task" => serde_json::json!({
            "type": "object",
            "properties": {
                "description": {
                    "type": "string",
                    "description": "Short (3-5 word) description of the task"
                },
                "prompt": {
                    "type": "string",
                    "description": "Detailed instructions for the subagent"
                },
                "run_in_background": {
                    "type": "boolean",
                    "description": "If true, run in background and return immediately. Default: false."
                },
                "agent": {
                    "type": "string",
                    "enum": ["auto", "claude", "codex", "llm"],
                    "description": "Which coding agent to use. 'auto' picks the best available CLI. Default: auto."
                }
            },
            "required": ["description", "prompt"]
        }),
        _ if name.starts_with("skill_") => serde_json::json!({
            "type": "object",
            "properties": {
                "args": {
                    "type": "string",
                    "description": "Space-separated arguments to pass to the skill command"
                }
            },
            "required": ["args"]
        }),
        _ => serde_json::json!({"type": "object", "properties": {}}),
    }
}

/// Build LLM tool definitions from a list of tool descriptions.
pub fn build_tool_definitions(descs: &[ToolDescription]) -> Option<serde_json::Value> {
    use aegis_types::llm::LlmToolDefinition;

    let defs: Vec<LlmToolDefinition> = descs
        .iter()
        .map(|td| LlmToolDefinition {
            name: td.name.clone(),
            description: td.description.clone(),
            input_schema: tool_schema_for(&td.name),
        })
        .collect();

    serde_json::to_value(&defs).ok()
}

/// Get tool definitions as JSON for the LLM request.
///
/// Returns the serialized tool definitions that will be passed to
/// `DaemonCommand::LlmComplete { tools }`.
pub fn get_tool_definitions_json(skills: &aegis_skills::SkillRegistry) -> Option<serde_json::Value> {
    build_tool_definitions(&get_tool_descriptions(skills))
}

/// Create a short summary of a tool call's input for display.
pub fn summarize_tool_input(name: &str, input: &serde_json::Value) -> String {
    match name {
        "bash" => input
            .get("command")
            .and_then(|v| v.as_str())
            .map(|s| {
                if s.len() > 80 {
                    format!("{}...", &s[..80])
                } else {
                    s.to_string()
                }
            })
            .unwrap_or_default(),
        "read_file" => input
            .get("file_path")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string(),
        "write_file" => {
            let path = input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let len = input
                .get("content")
                .and_then(|v| v.as_str())
                .map(|s| s.len())
                .unwrap_or(0);
            format!("{path} ({len} bytes)")
        }
        "edit_file" => input
            .get("file_path")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string(),
        "glob_search" => input
            .get("pattern")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string(),
        "grep_search" => input
            .get("pattern")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string(),
        "apply_patch" => {
            let patch = input.get("patch").and_then(|v| v.as_str()).unwrap_or("");
            // Show the first file operation from the patch.
            patch
                .lines()
                .find(|l| {
                    l.starts_with("*** Add File:")
                        || l.starts_with("*** Update File:")
                        || l.starts_with("*** Delete File:")
                })
                .unwrap_or("patch")
                .to_string()
        }
        "file_search" => input
            .get("query")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string(),
        "task" => input
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("subagent task")
            .to_string(),
        _ if name.starts_with("skill_") => {
            let cmd = name.strip_prefix("skill_").unwrap_or(name);
            let args = input
                .get("args")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            format!("/{cmd} {args}")
        }
        _ => serde_json::to_string(input)
            .unwrap_or_default()
            .chars()
            .take(100)
            .collect(),
    }
}

/// Format a tool call's full content for display in the chat.
pub fn format_tool_call_content(name: &str, input: &serde_json::Value) -> String {
    match name {
        "bash" => input
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        "read_file" | "edit_file" => input
            .get("file_path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        "apply_patch" => input
            .get("patch")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        "file_search" => input
            .get("query")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        _ if name.starts_with("skill_") => {
            let cmd = name.strip_prefix("skill_").unwrap_or(name);
            let args = input
                .get("args")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            format!("/{cmd} {args}")
        }
        _ => serde_json::to_string_pretty(input).unwrap_or_default(),
    }
}

/// Format a `SkillOutput` for display in the chat area.
pub fn format_skill_output(command: &str, output: &aegis_skills::SkillOutput) -> String {
    let mut text = String::new();
    // Show the result.
    let result_str = match &output.result {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => "(no output)".to_string(),
        other => serde_json::to_string_pretty(other).unwrap_or_else(|_| other.to_string()),
    };
    text.push_str(&format!("[/{command}] {result_str}"));

    // Append any messages.
    for msg in &output.messages {
        text.push('\n');
        text.push_str(msg);
    }

    // Note artifacts.
    if !output.artifacts.is_empty() {
        text.push_str(&format!(
            "\n({} artifact(s) produced)",
            output.artifacts.len()
        ));
    }

    text
}
