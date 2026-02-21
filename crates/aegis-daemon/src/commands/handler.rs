//! Core command handler types: context, result, and trait.
//!
//! Every command in the framework implements [`CommandDef`], which provides
//! metadata (name, aliases, help) and an `execute` method. Commands receive
//! a [`CommandContext`] describing who is invoking the command and from where,
//! and return a [`CommandResult`] with the outcome.

use anyhow::Result;

/// Execution context passed to every command handler.
///
/// Contains the identity of the caller, the channel through which the command
/// was issued, and the parsed arguments.
#[derive(Debug, Clone)]
pub struct CommandContext {
    /// Agent ID associated with this command (empty for fleet-level commands).
    pub agent_id: String,
    /// Principal performing the action (e.g., "user", "telegram-bot", agent name).
    pub principal: String,
    /// Channel through which the command was issued ("tui", "telegram", "daemon", "http").
    pub channel: String,
    /// Parsed positional arguments (excluding the command name itself).
    pub args: Vec<String>,
    /// Original raw input string before parsing.
    pub raw_input: String,
}

/// Result of executing a command.
#[derive(Debug, Clone)]
pub struct CommandResult {
    /// Whether the command succeeded.
    pub success: bool,
    /// Human-readable message describing the outcome.
    pub message: String,
    /// Optional structured data for programmatic consumption.
    pub data: Option<serde_json::Value>,
}

impl CommandResult {
    /// Create a successful result with a message.
    pub fn ok(message: impl Into<String>) -> Self {
        Self {
            success: true,
            message: message.into(),
            data: None,
        }
    }

    /// Create a successful result with a message and structured data.
    pub fn ok_with_data(message: impl Into<String>, data: serde_json::Value) -> Self {
        Self {
            success: true,
            message: message.into(),
            data: Some(data),
        }
    }

    /// Create a failure result with an error message.
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success: false,
            message: message.into(),
            data: None,
        }
    }
}

/// Trait that all framework commands must implement.
///
/// Commands are registered in the [`super::registry::CommandRegistry`] and
/// dispatched by the [`super::router::CommandRouter`]. Each command declares
/// its name, aliases, help text, and the Cedar action required for permission
/// checks.
///
/// # Security
///
/// The `required_action` method returns the Cedar action name that must be
/// permitted for the calling principal before `execute` is invoked. The router
/// enforces this check before dispatching.
pub trait CommandDef: Send + Sync {
    /// Primary command name (e.g., "status"). Must be lowercase alphanumeric
    /// with optional hyphens.
    fn name(&self) -> &str;

    /// Alternative names for this command (e.g., ["s", "st"]).
    fn aliases(&self) -> Vec<&str> {
        vec![]
    }

    /// One-line description shown in help listings.
    fn description(&self) -> &str;

    /// Usage pattern shown in detailed help (e.g., "status [agent]").
    fn usage(&self) -> &str;

    /// Cedar action name required for permission check (e.g., "ToolCall").
    fn required_action(&self) -> &str;

    /// Execute the command with the given context.
    fn execute(&self, ctx: &CommandContext) -> Result<CommandResult>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_result_ok() {
        let r = CommandResult::ok("done");
        assert!(r.success);
        assert_eq!(r.message, "done");
        assert!(r.data.is_none());
    }

    #[test]
    fn test_command_result_ok_with_data() {
        let r = CommandResult::ok_with_data("done", serde_json::json!({"count": 3}));
        assert!(r.success);
        assert!(r.data.is_some());
    }

    #[test]
    fn test_command_result_error() {
        let r = CommandResult::error("failed");
        assert!(!r.success);
        assert_eq!(r.message, "failed");
    }
}
