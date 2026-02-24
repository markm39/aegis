//! System prompt construction for chat TUI LLM requests.
//!
//! Builds a modular system prompt with sections adapted from OpenClaw's
//! architecture and Codex's coding agent instructions. Sections are stored
//! as static markdown files and included at compile time.

use std::fmt::Write;
use std::path::Path;
use std::process::Command;

/// Maximum characters to include from any single project context file.
const MAX_FILE_CHARS: usize = 20_000;

/// Maximum total characters for the entire system prompt.
const MAX_PROMPT_CHARS: usize = 100_000;

// Static prompt sections included at compile time.
const IDENTITY: &str = include_str!("prompts/identity.md");
const TOOLING_STYLE: &str = include_str!("prompts/tooling.md");
const SAFETY: &str = include_str!("prompts/safety.md");
const CODING: &str = include_str!("prompts/coding.md");
const OUTPUT_FORMATTING: &str = include_str!("prompts/output_formatting.md");
const APPLY_PATCH_INSTRUCTIONS: &str =
    include_str!("../../../../vendor/codex/apply-patch/apply_patch_tool_instructions.md");

/// Controls which sections are included in the system prompt.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PromptMode {
    /// Full prompt (main agent): all sections included.
    Full,
    /// Minimal prompt (subagents): only tooling, workspace, and runtime info.
    Minimal,
}

/// Minimal tool description for system prompt construction.
pub struct ToolDescription {
    /// Tool name (e.g. "read_file", "bash").
    pub name: String,
    /// Human-readable description of what the tool does.
    pub description: String,
}

/// Build the system prompt for chat TUI LLM requests.
///
/// Assembles modular sections in order:
/// 1. Identity (always)
/// 2. Available tools (always)
/// 3. Tool call style (full only)
/// 4. Safety (full only)
/// 5. Coding agent instructions (full only)
/// 6. apply_patch format spec (always -- subagents use it too)
/// 7. Output formatting (full only)
/// 8. Approval mode (always, if provided)
/// 9. Workspace / environment (always)
/// 10. Project context files (always)
/// 11. Git info (always)
pub fn build_system_prompt(
    tool_descriptions: &[ToolDescription],
    approval_context: Option<&str>,
    mode: PromptMode,
) -> String {
    let is_full = mode == PromptMode::Full;
    let mut prompt = String::with_capacity(if is_full { 16384 } else { 4096 });

    // 1. Identity
    prompt.push_str(IDENTITY);

    // 2. Available tools
    if !tool_descriptions.is_empty() {
        prompt.push_str("\n# Available Tools\n\n");
        prompt.push_str("Tool names are case-sensitive. Call tools exactly as listed.\n\n");
        for tool in tool_descriptions {
            let _ = writeln!(prompt, "- **{}**: {}", tool.name, tool.description);
        }
    }

    // 3. Tool call style (full only)
    if is_full {
        prompt.push('\n');
        prompt.push_str(TOOLING_STYLE);
    }

    // 4. Safety (full only)
    if is_full {
        prompt.push('\n');
        prompt.push_str(SAFETY);
    }

    // 5. Coding agent instructions (full only)
    if is_full {
        prompt.push('\n');
        prompt.push_str(CODING);
    }

    // 6. apply_patch format spec (always -- subagents need it too)
    prompt.push('\n');
    prompt.push_str(APPLY_PATCH_INSTRUCTIONS);

    // 7. Output formatting (full only)
    if is_full {
        prompt.push('\n');
        prompt.push_str(OUTPUT_FORMATTING);
    }

    // 8. Approval mode
    if let Some(ctx) = approval_context {
        prompt.push_str("\n# Approval Mode\n\n");
        prompt.push_str(ctx);
        prompt.push('\n');
    }

    // 9. Workspace / environment
    prompt.push_str("\n# Workspace\n\n");
    if let Ok(cwd) = std::env::current_dir() {
        let _ = writeln!(prompt, "- Working directory: `{}`", cwd.display());
    }
    let _ = writeln!(prompt, "- OS: {}", std::env::consts::OS);
    let _ = writeln!(prompt, "- Architecture: {}", std::env::consts::ARCH);
    prompt.push_str(
        "\nTreat this directory as the workspace for file operations \
         unless explicitly instructed otherwise.\n",
    );

    // 10. Workspace context files (~/.aegis/workspace/)
    //
    // These are the agent's persistent identity and personality files,
    // seeded on first run and updated by the agent over time.
    // Session-type filtering: subagents only get IDENTITY.md + TOOLS.md.
    let ws = aegis_types::daemon::workspace_dir();
    let workspace_files: &[(&str, &str, bool)] = &[
        // (filename, label, full_only)
        ("SOUL.md", "SOUL.md", true), // full only -- personality
        ("IDENTITY.md", "IDENTITY.md", false), // always -- agent name
        ("USER.md", "USER.md", true), // full only -- personal
        ("TOOLS.md", "TOOLS.md", false), // always -- environment
        ("MEMORY.md", "MEMORY.md", true), // full only -- persistent memory
        ("HEARTBEAT.md", "HEARTBEAT.md", true), // full only -- session checklist
    ];

    let mut has_ws_context = false;
    let mut has_soul = false;
    let mut has_memory = false;
    let mut has_heartbeat = false;
    for &(filename, label, full_only) in workspace_files {
        if full_only && !is_full {
            continue;
        }
        let path = ws.join(filename);
        if let Some(contents) = read_file_capped(&path, MAX_FILE_CHARS) {
            if !has_ws_context {
                prompt.push_str("\n# Agent Context\n\n");
                prompt.push_str(
                    "The following workspace context files define your identity \
                     and personality. They persist across sessions.\n",
                );
                has_ws_context = true;
            }
            if filename == "SOUL.md" {
                has_soul = true;
            }
            if filename == "MEMORY.md" {
                has_memory = true;
            }
            if filename == "HEARTBEAT.md" {
                has_heartbeat = true;
            }
            let _ = writeln!(prompt, "\n## {label}\n");
            prompt.push_str(&contents);
            prompt.push('\n');
        }
    }

    // Special instruction when SOUL.md is present
    if has_soul {
        prompt.push_str(
            "\nIf SOUL.md is present above, embody its persona and tone. \
             Avoid stiff, generic replies; follow its guidance unless \
             higher-priority instructions override it.\n",
        );
    }

    // Special instruction when MEMORY.md is present
    if has_memory {
        prompt.push_str(
            "\nMEMORY.md above contains your persistent notes from prior \
             sessions. Reference it for context. Update it with new learnings \
             using write_file when you discover important information.\n",
        );
    }

    // Special instruction when HEARTBEAT.md is present
    if has_heartbeat {
        prompt.push_str(
            "\nIf HEARTBEAT.md has checklist items above, review them at the \
             start of the session. Report anything that needs attention. \
             If all items are clear, proceed normally.\n",
        );
    }

    // 11. Project context files (from CWD)
    let cwd = std::env::current_dir().unwrap_or_default();
    let project_files: &[(&str, std::path::PathBuf)] = &[
        ("AGENTS.md", cwd.join("AGENTS.md")),
        ("CLAUDE.md", cwd.join("CLAUDE.md")),
        (".aegis/AGENTS.md", cwd.join(".aegis/AGENTS.md")),
    ];

    let mut has_project_context = false;
    for (label, path) in project_files {
        if let Some(contents) = read_file_capped(path, MAX_FILE_CHARS) {
            if !has_project_context {
                prompt.push_str("\n# Project Context\n\n");
                prompt.push_str("The following project context files have been loaded.\n\n");
                has_project_context = true;
            }
            let _ = writeln!(prompt, "## {label}\n");
            prompt.push_str(&contents);
            prompt.push('\n');
        }
    }

    // 12. Git info
    if let Some(git_section) = build_git_section(&cwd) {
        prompt.push_str(&git_section);
    }

    // Cap total prompt length
    if prompt.len() > MAX_PROMPT_CHARS {
        prompt.truncate(MAX_PROMPT_CHARS);
        prompt.push_str("\n\n[System prompt truncated due to length]\n");
    }

    prompt
}

/// Read a file's contents, returning `None` if it doesn't exist or can't be read.
/// Truncates at `max_chars` characters.
fn read_file_capped(path: &Path, max_chars: usize) -> Option<String> {
    let contents = std::fs::read_to_string(path).ok()?;
    if contents.len() > max_chars {
        let mut truncated = contents[..max_chars].to_string();
        truncated.push_str("\n[...truncated]");
        Some(truncated)
    } else {
        Some(contents)
    }
}

/// Build the git information section, or `None` if git is unavailable or
/// the current directory is not a git repository.
fn build_git_section(cwd: &Path) -> Option<String> {
    let branch_output = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .current_dir(cwd)
        .output()
        .ok()?;

    if !branch_output.status.success() {
        return None;
    }

    let branch = String::from_utf8_lossy(&branch_output.stdout)
        .trim()
        .to_string();

    let mut section = String::from("\n# Git Info\n\n");
    let _ = writeln!(section, "- Branch: `{branch}`");

    if let Ok(status_output) = Command::new("git")
        .args(["status", "--short"])
        .current_dir(cwd)
        .output()
    {
        if status_output.status.success() {
            let status = String::from_utf8_lossy(&status_output.stdout);
            let status = status.trim();
            if status.is_empty() {
                section.push_str("- Working tree: clean\n");
            } else {
                section.push_str("- Working tree changes:\n```\n");
                section.push_str(status);
                section.push_str("\n```\n");
            }
        }
    }

    Some(section)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_system_prompt_returns_non_empty() {
        let prompt = build_system_prompt(&[], None, PromptMode::Full);
        assert!(!prompt.is_empty());
    }

    #[test]
    fn prompt_contains_identity() {
        let prompt = build_system_prompt(&[], None, PromptMode::Full);
        assert!(prompt.contains("You are Aegis"));
        assert!(prompt.contains("autonomous coding agent"));
    }

    #[test]
    fn prompt_contains_workspace() {
        let prompt = build_system_prompt(&[], None, PromptMode::Full);
        assert!(prompt.contains("# Workspace"));
        assert!(prompt.contains("OS:"));
        assert!(prompt.contains("Architecture:"));
    }

    #[test]
    fn prompt_includes_tool_descriptions() {
        let tools = vec![
            ToolDescription {
                name: "read_file".into(),
                description: "Read a file from disk".into(),
            },
            ToolDescription {
                name: "bash".into(),
                description: "Run a shell command".into(),
            },
        ];
        let prompt = build_system_prompt(&tools, None, PromptMode::Full);
        assert!(prompt.contains("# Available Tools"));
        assert!(prompt.contains("read_file"));
        assert!(prompt.contains("Run a shell command"));
    }

    #[test]
    fn prompt_omits_tools_section_when_empty() {
        let prompt = build_system_prompt(&[], None, PromptMode::Full);
        assert!(!prompt.contains("# Available Tools"));
    }

    #[test]
    fn prompt_full_includes_coding_instructions() {
        let prompt = build_system_prompt(&[], None, PromptMode::Full);
        assert!(prompt.contains("AGENTS.md"));
        assert!(prompt.contains("Keep going until"));
        assert!(prompt.contains("apply_patch"));
    }

    #[test]
    fn prompt_full_includes_safety() {
        let prompt = build_system_prompt(&[], None, PromptMode::Full);
        assert!(prompt.contains("# Safety"));
        assert!(prompt.contains("self-preservation"));
    }

    #[test]
    fn prompt_full_includes_output_formatting() {
        let prompt = build_system_prompt(&[], None, PromptMode::Full);
        assert!(prompt.contains("# Output Formatting"));
        assert!(prompt.contains("concise"));
    }

    #[test]
    fn prompt_includes_apply_patch_format() {
        // apply_patch format is included in both modes
        let full = build_system_prompt(&[], None, PromptMode::Full);
        assert!(full.contains("Begin Patch"));
        assert!(full.contains("End Patch"));

        let minimal = build_system_prompt(&[], None, PromptMode::Minimal);
        assert!(minimal.contains("Begin Patch"));
        assert!(minimal.contains("End Patch"));
    }

    #[test]
    fn prompt_minimal_omits_full_sections() {
        let prompt = build_system_prompt(&[], None, PromptMode::Minimal);
        // Minimal should not include coding, safety, or output formatting
        assert!(!prompt.contains("# Coding Agent Instructions"));
        assert!(!prompt.contains("# Safety"));
        assert!(!prompt.contains("# Output Formatting"));
        assert!(!prompt.contains("# Tool Call Style"));
    }

    #[test]
    fn prompt_minimal_includes_essentials() {
        let tools = vec![ToolDescription {
            name: "bash".into(),
            description: "Run a shell command".into(),
        }];
        let prompt = build_system_prompt(&tools, Some("Full auto."), PromptMode::Minimal);
        // Minimal still includes identity, tools, apply_patch, workspace, approval
        assert!(prompt.contains("You are Aegis"));
        assert!(prompt.contains("# Available Tools"));
        assert!(prompt.contains("Begin Patch"));
        assert!(prompt.contains("# Workspace"));
        assert!(prompt.contains("# Approval Mode"));
        assert!(prompt.contains("Full auto."));
    }

    #[test]
    fn read_file_capped_returns_none_for_missing() {
        let result = read_file_capped(Path::new("/nonexistent/file.txt"), MAX_FILE_CHARS);
        assert!(result.is_none());
    }

    #[test]
    fn read_file_capped_truncates_long_content() {
        let dir = std::env::temp_dir().join("aegis_test_system_prompt");
        let _ = std::fs::create_dir_all(&dir);
        let file_path = dir.join("long_file.txt");
        let long_content = "x".repeat(100);
        std::fs::write(&file_path, &long_content).unwrap();

        let result = read_file_capped(&file_path, 50).unwrap();
        assert!(result.len() < long_content.len());
        assert!(result.contains("[...truncated]"));

        let _ = std::fs::remove_file(&file_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn prompt_respects_max_length() {
        let prompt = build_system_prompt(&[], None, PromptMode::Full);
        assert!(prompt.len() <= MAX_PROMPT_CHARS + 100);
    }

    #[test]
    fn prompt_includes_approval_context() {
        let prompt = build_system_prompt(&[], Some("All tools auto-approved."), PromptMode::Full);
        assert!(prompt.contains("# Approval Mode"));
        assert!(prompt.contains("All tools auto-approved."));
    }

    #[test]
    fn prompt_omits_approval_section_when_none() {
        let prompt = build_system_prompt(&[], None, PromptMode::Full);
        assert!(!prompt.contains("# Approval Mode"));
    }
}
