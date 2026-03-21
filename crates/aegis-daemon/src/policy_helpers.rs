//! Hook policy helpers: tool-name mapping, interactive tool detection,
//! autonomy prompts, and the fail-open environment flag.

use aegis_types::daemon::AgentSlotConfig;
use aegis_types::{ActionKind};

/// Whether hook policy checks should fail open on control/policy failures.
///
/// Defaults to fail-closed. Set `AEGIS_HOOK_FAIL_OPEN=1` (or true/yes/on)
/// only for lower-trust development environments.
pub(crate) fn hook_fail_open_enabled() -> bool {
    std::env::var("AEGIS_HOOK_FAIL_OPEN")
        .ok()
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            matches!(v.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

/// Map a Claude Code tool use into an Aegis `ActionKind` for Cedar policy evaluation.
///
/// Claude Code hooks provide `tool_name` (e.g., "Bash", "Read", "Write") and
/// `tool_input` (JSON with tool-specific parameters). We map these to the
/// corresponding `ActionKind` so Cedar policies can make fine-grained decisions
/// about file paths, commands, URLs, etc.
pub(crate) fn map_tool_use_to_action(
    tool_name: &str,
    tool_input: &serde_json::Value,
) -> ActionKind {
    match tool_name {
        "Bash" => {
            let command = tool_input
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            ActionKind::ProcessSpawn {
                command,
                args: vec![],
            }
        }
        "Read" | "NotebookRead" => {
            let path = tool_input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .into();
            ActionKind::FileRead { path }
        }
        "Write" => {
            let path = tool_input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .into();
            ActionKind::FileWrite { path }
        }
        "Edit" => {
            let path = tool_input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .into();
            ActionKind::FileWrite { path }
        }
        "NotebookEdit" => {
            let path = tool_input
                .get("notebook_path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .into();
            ActionKind::FileWrite { path }
        }
        "Glob" | "Grep" | "LS" => {
            let path = tool_input
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or(".")
                .into();
            ActionKind::DirList { path }
        }
        "WebFetch" => {
            let url = tool_input
                .get("url")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            ActionKind::NetRequest {
                method: "GET".to_string(),
                url,
            }
        }
        "WebSearch" => {
            let query = tool_input
                .get("query")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            ActionKind::NetRequest {
                method: "GET".to_string(),
                url: query,
            }
        }
        _ => ActionKind::ToolCall {
            tool: tool_name.to_string(),
            args: tool_input.clone(),
        },
    }
}

/// Tools that require human interaction and would stall a headless agent.
///
/// Only `AskUserQuestion` is blocked -- it genuinely waits for human input
/// and would stall a headless agent indefinitely.
///
/// Plan mode tools (`EnterPlanMode`, `ExitPlanMode`) are intentionally allowed.
/// Plan mode produces better results by giving CC time to research and design
/// before implementing. With `--dangerously-skip-permissions`, `ExitPlanMode`
/// auto-approves so the agent flows through plan -> implement without stalling.
pub(crate) fn is_interactive_tool(tool_name: &str) -> bool {
    tool_name == "AskUserQuestion"
}

pub(crate) fn is_known_policy_tool(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "Bash"
            | "Read"
            | "NotebookRead"
            | "Write"
            | "Edit"
            | "NotebookEdit"
            | "Glob"
            | "Grep"
            | "LS"
            | "WebFetch"
            | "WebSearch"
            | "AskUserQuestion"
            | "EnterPlanMode"
            | "ExitPlanMode"
    )
}

/// Compose a denial reason that guides the model to proceed autonomously.
///
/// Includes the agent's role, goal, context, and task (if configured) so the
/// model has enough information to make decisions without human input. Also
/// includes the fleet-wide goal if set.
pub(crate) fn compose_autonomy_prompt(
    tool_name: &str,
    fleet_goal: Option<&str>,
    agent_config: Option<&AgentSlotConfig>,
) -> String {
    let mut sections = Vec::new();

    sections.push(format!(
        "You are running as an autonomous agent managed by Aegis. \
         {tool_name} is not available in headless mode -- proceed without it."
    ));

    if let Some(goal) = fleet_goal {
        if !goal.is_empty() {
            sections.push(format!("Fleet mission: {goal}"));
        }
    }

    if let Some(config) = agent_config {
        if let Some(ref role) = config.role {
            if !role.is_empty() {
                sections.push(format!("Your role: {role}"));
            }
        }
        if let Some(ref goal) = config.agent_goal {
            if !goal.is_empty() {
                sections.push(format!("Your goal: {goal}"));
            }
        }
        if let Some(ref ctx) = config.context {
            if !ctx.is_empty() {
                sections.push(format!("Context: {ctx}"));
            }
        }
        if let Some(ref task) = config.task {
            if !task.is_empty() {
                sections.push(format!("Your task: {task}"));
            }
        }
    }

    // Only AskUserQuestion is denied, so guidance is always about autonomous decisions.
    sections.push(
        "Make decisions autonomously based on your role and context. \
         Do not ask clarifying questions -- use your best judgment and proceed."
            .to_string(),
    );

    sections.join(" ")
}
