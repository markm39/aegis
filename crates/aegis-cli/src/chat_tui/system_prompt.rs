//! System prompt construction for chat TUI LLM requests.
//!
//! Builds a rich system prompt that includes identity, available tools,
//! environment info, project context files, and git status.

use std::fmt::Write;
use std::path::Path;
use std::process::Command;

/// Maximum characters to include from any single project context file.
const MAX_FILE_CHARS: usize = 20_000;

/// Maximum total characters for the entire system prompt.
const MAX_PROMPT_CHARS: usize = 100_000;

/// Minimal tool description for system prompt construction.
pub struct ToolDescription {
    /// Tool name (e.g. "read_file", "bash").
    pub name: String,
    /// Human-readable description of what the tool does.
    pub description: String,
}

/// Build the system prompt for chat TUI LLM requests.
///
/// Includes: identity, available tools, working directory, OS info,
/// project files (AGENTS.md, CLAUDE.md), and git status.
pub fn build_system_prompt(tool_descriptions: &[ToolDescription]) -> String {
    let mut prompt = String::with_capacity(4096);

    // 1. Identity
    prompt.push_str(
        "You are Aegis, a helpful coding assistant. You have access to tools \
         for reading files, editing code, running commands, and searching the codebase.\n",
    );

    // 2. Available tools
    if !tool_descriptions.is_empty() {
        prompt.push_str("\n# Available Tools\n\n");
        for tool in tool_descriptions {
            let _ = writeln!(prompt, "- **{}**: {}", tool.name, tool.description);
        }
    }

    // 3. Environment
    prompt.push_str("\n# Environment\n\n");
    if let Ok(cwd) = std::env::current_dir() {
        let _ = writeln!(prompt, "- Working directory: {}", cwd.display());
    }
    let _ = writeln!(prompt, "- OS: {}", std::env::consts::OS);
    let _ = writeln!(prompt, "- Architecture: {}", std::env::consts::ARCH);

    // 4. Project context files
    let cwd = std::env::current_dir().unwrap_or_default();
    let context_files: &[(&str, std::path::PathBuf)] = &[
        ("AGENTS.md", cwd.join("AGENTS.md")),
        ("CLAUDE.md", cwd.join("CLAUDE.md")),
        (".aegis/AGENTS.md", cwd.join(".aegis/AGENTS.md")),
    ];

    for (label, path) in context_files {
        if let Some(contents) = read_file_capped(path, MAX_FILE_CHARS) {
            let _ = writeln!(prompt, "\n# Project Context: {label}\n");
            prompt.push_str(&contents);
            prompt.push('\n');
        }
    }

    // 5. Git info
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
    // Check if we're in a git repo by getting the current branch.
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
    let _ = writeln!(section, "- Branch: {branch}");

    // Get brief status
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
        let prompt = build_system_prompt(&[]);
        assert!(!prompt.is_empty());
    }

    #[test]
    fn prompt_contains_identity() {
        let prompt = build_system_prompt(&[]);
        assert!(prompt.contains("You are Aegis"));
        assert!(prompt.contains("helpful coding assistant"));
    }

    #[test]
    fn prompt_contains_environment() {
        let prompt = build_system_prompt(&[]);
        assert!(prompt.contains("# Environment"));
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
        let prompt = build_system_prompt(&tools);
        assert!(prompt.contains("# Available Tools"));
        assert!(prompt.contains("read_file"));
        assert!(prompt.contains("Run a shell command"));
    }

    #[test]
    fn prompt_omits_tools_section_when_empty() {
        let prompt = build_system_prompt(&[]);
        assert!(!prompt.contains("# Available Tools"));
    }

    #[test]
    fn read_file_capped_returns_none_for_missing() {
        let result = read_file_capped(Path::new("/nonexistent/file.txt"), MAX_FILE_CHARS);
        assert!(result.is_none());
    }

    #[test]
    fn read_file_capped_truncates_long_content() {
        // Create a temp file with known content
        let dir = std::env::temp_dir().join("aegis_test_system_prompt");
        let _ = std::fs::create_dir_all(&dir);
        let file_path = dir.join("long_file.txt");
        let long_content = "x".repeat(100);
        std::fs::write(&file_path, &long_content).unwrap();

        let result = read_file_capped(&file_path, 50).unwrap();
        assert!(result.len() < long_content.len());
        assert!(result.contains("[...truncated]"));

        // Cleanup
        let _ = std::fs::remove_file(&file_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn prompt_respects_max_length() {
        // With no tools and no project files, the prompt should be well under the cap.
        let prompt = build_system_prompt(&[]);
        assert!(prompt.len() <= MAX_PROMPT_CHARS + 100); // small margin for truncation suffix
    }
}
