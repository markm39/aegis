//! Tool approval profiles and risk classification for the agentic loop.

use aegis_types::tool_classification::ActionRisk;

/// Tools that are auto-approved (read-only, safe operations).
pub const SAFE_TOOLS: &[&str] = &[
    "read_file",
    "glob_search",
    "grep_search",
    "file_search",
    "task",
];

/// Check whether a tool should be auto-approved.
pub fn is_safe_tool(name: &str) -> bool {
    SAFE_TOOLS.contains(&name)
}

/// Approval profile controlling which tool calls are auto-approved.
///
/// Inspired by Codex's suggest/auto-edit/full-auto modes and Claude Code's
/// permission profiles. Wires the existing `ActionRisk` classification into
/// the chat TUI's agentic loop.
#[derive(Debug, Clone, PartialEq)]
pub enum ApprovalProfile {
    /// Default: only SAFE_TOOLS auto-approved. Everything else asks.
    Manual,
    /// Auto-approve tools whose classified risk is at or below the given tier.
    AutoApprove(ActionRisk),
    /// Full-auto: approve everything without asking.
    FullAuto,
}

/// Classify the risk of a tool call for approval profile decisions.
pub fn classify_tool_risk(tool_name: &str, input: &serde_json::Value) -> ActionRisk {
    match tool_name {
        "read_file" | "glob_search" | "grep_search" | "file_search" => ActionRisk::Informational,
        "write_file" | "edit_file" | "apply_patch" => ActionRisk::Medium,
        "bash" => classify_bash_risk(input),
        "task" => ActionRisk::Medium,
        _ if tool_name.starts_with("skill_") => ActionRisk::Medium,
        _ => ActionRisk::High,
    }
}

/// Classify bash command risk by inspecting the command string.
///
/// Read-only commands (ls, cat, git status) are Low risk.
/// Destructive commands (rm -rf, force push, sudo) are High risk.
/// Git mutations and general commands default to Medium.
pub fn classify_bash_risk(input: &serde_json::Value) -> ActionRisk {
    let cmd = input.get("command").and_then(|v| v.as_str()).unwrap_or("");

    let read_only_prefixes = [
        "cat ",
        "ls ",
        "ls\n",
        "pwd",
        "echo ",
        "head ",
        "tail ",
        "wc ",
        "grep ",
        "rg ",
        "find ",
        "which ",
        "type ",
        "file ",
        "git status",
        "git log",
        "git diff",
        "git branch",
        "git show",
        "git rev-parse",
        "cargo clippy",
        "cargo check",
        "cargo test",
        "cargo build",
        "npm test",
        "npm run",
        "python -c",
        "node -e",
    ];
    if read_only_prefixes.iter().any(|p| cmd.starts_with(p)) {
        return ActionRisk::Low;
    }

    let destructive_patterns = [
        "rm -rf",
        "rm -r",
        "rmdir",
        "git push --force",
        "git push -f",
        "git reset --hard",
        "git clean",
        "drop table",
        "drop database",
        "docker rm",
        "kill -9",
        "sudo ",
        "chmod 777",
    ];
    if destructive_patterns.iter().any(|p| cmd.contains(p)) {
        return ActionRisk::High;
    }

    let git_write = [
        "git add",
        "git commit",
        "git push",
        "git checkout",
        "git stash",
    ];
    if git_write.iter().any(|p| cmd.starts_with(p)) {
        return ActionRisk::Medium;
    }

    ActionRisk::Medium
}

/// Check if a tool call should be auto-approved given the current profile.
pub fn should_auto_approve_tool(
    tool_name: &str,
    tool_input: &serde_json::Value,
    auto_approve_all: bool,
    profile: &ApprovalProfile,
) -> bool {
    match profile {
        ApprovalProfile::FullAuto => true,
        ApprovalProfile::Manual => is_safe_tool(tool_name) || auto_approve_all,
        ApprovalProfile::AutoApprove(max_risk) => {
            if is_safe_tool(tool_name) || auto_approve_all {
                true
            } else {
                classify_tool_risk(tool_name, tool_input) <= *max_risk
            }
        }
    }
}

/// Return a display label for the current approval profile.
pub fn approval_profile_label(profile: &ApprovalProfile) -> &'static str {
    match profile {
        ApprovalProfile::Manual => "manual",
        ApprovalProfile::AutoApprove(ActionRisk::Low) => "auto-low",
        ApprovalProfile::AutoApprove(ActionRisk::Informational) => "auto-info",
        ApprovalProfile::AutoApprove(ActionRisk::Medium) => "auto-edits",
        ApprovalProfile::AutoApprove(ActionRisk::High) => "auto-high",
        ApprovalProfile::AutoApprove(_) => "auto-custom",
        ApprovalProfile::FullAuto => "full-auto",
    }
}

/// Parse an approval mode string into an `ApprovalProfile`.
///
/// Accepts: "off", "manual", "edits", "high", "full"
pub fn parse_approval_mode(mode: &str) -> ApprovalProfile {
    match mode {
        "off" | "manual" => ApprovalProfile::Manual,
        "edits" | "medium" => ApprovalProfile::AutoApprove(ActionRisk::Medium),
        "high" => ApprovalProfile::AutoApprove(ActionRisk::High),
        "full" | "full-auto" => ApprovalProfile::FullAuto,
        _ => {
            eprintln!(
                "Warning: unknown --auto mode '{mode}', using 'manual'. Options: off, edits, high, full"
            );
            ApprovalProfile::Manual
        }
    }
}

/// Return the approval context string for the system prompt.
pub fn approval_context_for_prompt(profile: &ApprovalProfile) -> &'static str {
    match profile {
        ApprovalProfile::Manual => {
            "Tools that modify files or run commands require user approval before execution. \
             Read-only tools (read_file, glob_search, grep_search, file_search) are auto-approved."
        }
        ApprovalProfile::AutoApprove(ActionRisk::Medium) => {
            "File edits, writes, and normal bash commands are auto-approved. \
             Destructive operations (rm -rf, force push, sudo, etc.) still require user approval. \
             You can work autonomously for most coding tasks."
        }
        ApprovalProfile::AutoApprove(ActionRisk::High) => {
            "Almost all tools are auto-approved, including high-risk operations. \
             Only critical/destructive commands require approval. You can work very autonomously."
        }
        ApprovalProfile::AutoApprove(_) => {
            "Tools are auto-approved up to the configured risk tier. \
             Higher-risk operations require user approval."
        }
        ApprovalProfile::FullAuto => {
            "All tools are auto-approved. You can work fully autonomously without waiting \
             for approval on any tool call. Execute multi-step plans without interruption."
        }
    }
}
