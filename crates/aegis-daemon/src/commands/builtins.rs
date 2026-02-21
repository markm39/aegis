//! Built-in commands: help, status, version.
//!
//! These commands are always available in any command registry. They provide
//! core introspection capabilities: listing commands, checking fleet status,
//! and reporting the aegis version.

use anyhow::Result;

use super::handler::{CommandContext, CommandDef, CommandResult};
use super::registry::CommandRegistry;

/// Register all built-in commands into the given registry.
pub fn register_builtins(registry: &mut CommandRegistry) {
    registry.register(Box::new(HelpCommand));
    registry.register(Box::new(StatusCommand));
    registry.register(Box::new(VersionCommand));
}

// ---------------------------------------------------------------------------
// HelpCommand
// ---------------------------------------------------------------------------

/// Lists available commands or shows detailed help for a specific command.
struct HelpCommand;

impl CommandDef for HelpCommand {
    fn name(&self) -> &str {
        "help"
    }

    fn aliases(&self) -> Vec<&str> {
        vec!["h", "?"]
    }

    fn description(&self) -> &str {
        "List available commands or show help for a specific command"
    }

    fn usage(&self) -> &str {
        "help [command]"
    }

    fn required_action(&self) -> &str {
        "ToolCall"
    }

    fn execute(&self, ctx: &CommandContext) -> Result<CommandResult> {
        // If a specific command name was provided, return detailed help.
        // We cannot access the registry from here directly, so we return
        // a generic listing. The router can intercept "help <cmd>" if needed.
        if ctx.args.is_empty() {
            Ok(CommandResult::ok(
                "Available commands: help, status, version. Use 'help <command>' for details.",
            ))
        } else {
            let target = &ctx.args[0];
            Ok(CommandResult::ok(format!(
                "Help requested for '{target}'. Use the registry's lookup_help() for full details."
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// StatusCommand
// ---------------------------------------------------------------------------

/// Returns agent/fleet status summary.
struct StatusCommand;

impl CommandDef for StatusCommand {
    fn name(&self) -> &str {
        "status"
    }

    fn aliases(&self) -> Vec<&str> {
        vec!["s", "st"]
    }

    fn description(&self) -> &str {
        "Show agent or fleet status summary"
    }

    fn usage(&self) -> &str {
        "status [agent]"
    }

    fn required_action(&self) -> &str {
        "ToolCall"
    }

    fn execute(&self, _ctx: &CommandContext) -> Result<CommandResult> {
        // Stub implementation. A real implementation would query the fleet.
        Ok(CommandResult::ok("status: ok"))
    }
}

// ---------------------------------------------------------------------------
// VersionCommand
// ---------------------------------------------------------------------------

/// Returns the aegis version (from Cargo package metadata).
struct VersionCommand;

impl CommandDef for VersionCommand {
    fn name(&self) -> &str {
        "version"
    }

    fn aliases(&self) -> Vec<&str> {
        vec!["v"]
    }

    fn description(&self) -> &str {
        "Show the aegis version"
    }

    fn usage(&self) -> &str {
        "version"
    }

    fn required_action(&self) -> &str {
        "ToolCall"
    }

    fn execute(&self, _ctx: &CommandContext) -> Result<CommandResult> {
        let version = env!("CARGO_PKG_VERSION");
        Ok(CommandResult::ok(format!("aegis {version}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx() -> CommandContext {
        CommandContext {
            agent_id: String::new(),
            principal: "user".into(),
            channel: "tui".into(),
            args: Vec::new(),
            raw_input: String::new(),
        }
    }

    #[test]
    fn test_help_command_lists_commands() {
        let cmd = HelpCommand;
        let ctx = make_ctx();
        let result = cmd.execute(&ctx).unwrap();
        assert!(result.success);
        assert!(result.message.contains("help"));
        assert!(result.message.contains("status"));
        assert!(result.message.contains("version"));
    }

    #[test]
    fn test_help_command_specific() {
        let cmd = HelpCommand;
        let mut ctx = make_ctx();
        ctx.args = vec!["status".into()];
        let result = cmd.execute(&ctx).unwrap();
        assert!(result.success);
        assert!(result.message.contains("status"));
    }

    #[test]
    fn test_status_command() {
        let cmd = StatusCommand;
        let ctx = make_ctx();
        let result = cmd.execute(&ctx).unwrap();
        assert!(result.success);
        assert!(result.message.contains("status: ok"));
    }

    #[test]
    fn test_version_command_returns_version() {
        let cmd = VersionCommand;
        let ctx = make_ctx();
        let result = cmd.execute(&ctx).unwrap();
        assert!(result.success);
        assert!(result.message.starts_with("aegis "));
        // Should contain a semver-like version string
        let version_str = result.message.strip_prefix("aegis ").unwrap();
        assert!(
            version_str.contains('.'),
            "version should contain a dot: {version_str}"
        );
    }

    #[test]
    fn test_register_builtins() {
        let mut registry = CommandRegistry::new();
        register_builtins(&mut registry);

        assert!(registry.lookup("help").is_some());
        assert!(registry.lookup("status").is_some());
        assert!(registry.lookup("version").is_some());

        // Aliases
        assert!(registry.lookup("h").is_some());
        assert!(registry.lookup("?").is_some());
        assert!(registry.lookup("s").is_some());
        assert!(registry.lookup("st").is_some());
        assert!(registry.lookup("v").is_some());

        // Deduplicated list
        let list = registry.list();
        assert_eq!(list.len(), 3);
    }
}
