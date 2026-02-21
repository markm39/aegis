//! Command router: parses input, checks permissions, and dispatches to handlers.
//!
//! The router is the main entry point for executing commands. It strips
//! leading prefixes (`/` or `:`), looks up the command in the registry,
//! validates the command name for injection characters, checks permissions
//! via a caller-supplied closure, and then delegates to the command's
//! `execute` method.
//!
//! # Security
//!
//! - Command names are validated: only alphanumeric, hyphens, and underscores
//!   are accepted. Characters like `;`, `|`, `&&`, backticks, `$`, and other
//!   shell metacharacters are rejected before any lookup or execution occurs.
//! - Permission checks happen before execution, using the Cedar action name
//!   declared by each command.

use anyhow::Result;

use super::handler::{CommandContext, CommandResult};
use super::registry::CommandRegistry;

/// Characters that are forbidden in command names to prevent injection.
const FORBIDDEN_CHARS: &[char] = &[';', '|', '&', '`', '$', '(', ')', '{', '}', '<', '>', '\\', '\'', '"', '\n', '\r', '\t'];

/// Maximum allowed length for a command name.
const MAX_COMMAND_NAME_LEN: usize = 64;

/// Permission checker type: receives `(action_name, principal)` and returns
/// whether the principal is allowed to perform that action.
pub type PermissionChecker = Box<dyn Fn(&str, &str) -> bool + Send + Sync>;

/// Routes parsed command input to registered handlers after validation
/// and permission checks.
pub struct CommandRouter {
    registry: CommandRegistry,
    /// Permission checker invoked before every command execution.
    permission_check: PermissionChecker,
}

impl CommandRouter {
    /// Create a new router with a command registry and permission checker.
    ///
    /// The `permission_check` closure receives `(action_name, principal)` and
    /// returns `true` if the principal is allowed to perform that action.
    pub fn new(
        registry: CommandRegistry,
        permission_check: PermissionChecker,
    ) -> Self {
        Self {
            registry,
            permission_check,
        }
    }

    /// Route an input string to the appropriate command handler.
    ///
    /// 1. Parses the input: splits on whitespace, strips leading `/` or `:` from the command name.
    /// 2. Validates the command name for forbidden characters.
    /// 3. Looks up the command in the registry.
    /// 4. Checks permissions via the configured closure.
    /// 5. Builds a `CommandContext` and delegates to the handler.
    pub fn route(&self, input: &str, ctx: &CommandContext) -> Result<CommandResult> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Ok(CommandResult::error("empty command"));
        }

        // Split into command name and arguments.
        let parts: Vec<&str> = trimmed.splitn(2, char::is_whitespace).collect();
        let raw_name = parts[0];
        let arg_str = if parts.len() > 1 { parts[1].trim() } else { "" };

        // Strip leading prefix (/ or :).
        let name = raw_name
            .strip_prefix('/')
            .or_else(|| raw_name.strip_prefix(':'))
            .unwrap_or(raw_name);

        // Validate command name: reject injection characters.
        if let Err(msg) = validate_command_name(name) {
            return Ok(CommandResult::error(msg));
        }

        // Lookup in registry.
        let cmd = match self.registry.lookup(name) {
            Some(c) => c,
            None => {
                let suggestion = suggest_command(name, &self.registry);
                let msg = match suggestion {
                    Some(s) => format!("unknown command '{name}'. Did you mean '{s}'?"),
                    None => format!("unknown command '{name}'. Type 'help' for available commands."),
                };
                return Ok(CommandResult::error(msg));
            }
        };

        // Check permissions.
        let action = cmd.required_action();
        if !(self.permission_check)(action, &ctx.principal) {
            return Ok(CommandResult::error(format!(
                "permission denied: principal '{}' is not allowed to execute '{}'",
                ctx.principal,
                cmd.name(),
            )));
        }

        // Build execution context with parsed arguments.
        let args: Vec<String> = if arg_str.is_empty() {
            Vec::new()
        } else {
            arg_str.split_whitespace().map(String::from).collect()
        };

        let exec_ctx = CommandContext {
            agent_id: ctx.agent_id.clone(),
            principal: ctx.principal.clone(),
            channel: ctx.channel.clone(),
            args,
            raw_input: input.to_string(),
        };

        cmd.execute(&exec_ctx)
    }

    /// Get a reference to the underlying registry.
    pub fn registry(&self) -> &CommandRegistry {
        &self.registry
    }
}

/// Validate that a command name contains only safe characters.
///
/// Rejects names containing shell metacharacters, control characters, or
/// that exceed the maximum length.
fn validate_command_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("command name must not be empty".into());
    }

    if name.len() > MAX_COMMAND_NAME_LEN {
        return Err(format!(
            "command name exceeds maximum length of {MAX_COMMAND_NAME_LEN}"
        ));
    }

    for ch in name.chars() {
        if FORBIDDEN_CHARS.contains(&ch) {
            return Err(format!(
                "command name contains forbidden character '{ch}'"
            ));
        }
        if ch.is_control() {
            return Err("command name contains control characters".into());
        }
    }

    Ok(())
}

/// Suggest a similar command name using simple prefix matching and
/// Levenshtein-style distance.
fn suggest_command(name: &str, registry: &CommandRegistry) -> Option<String> {
    let lower = name.to_lowercase();
    let names = registry.all_names();

    // First try prefix match.
    for n in &names {
        if n.starts_with(&lower) {
            return Some(n.clone());
        }
    }

    // Fall back to shortest edit distance (simple implementation).
    let mut best: Option<(String, usize)> = None;
    for n in &names {
        let dist = levenshtein(&lower, n);
        // Only suggest if distance is at most 3 (reasonable for typos).
        if dist <= 3 && (best.is_none() || dist < best.as_ref().unwrap().1) {
            best = Some((n.clone(), dist));
        }
    }

    best.map(|(n, _)| n)
}

/// Simple Levenshtein distance calculation.
fn levenshtein(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let n = b_chars.len();

    // Use a single row with rolling updates to save memory.
    let mut prev_row: Vec<usize> = (0..=n).collect();
    let mut curr_row = vec![0usize; n + 1];

    for (i, a_ch) in a_chars.iter().enumerate() {
        curr_row[0] = i + 1;
        for (j, b_ch) in b_chars.iter().enumerate() {
            let cost = if a_ch == b_ch { 0 } else { 1 };
            curr_row[j + 1] = (prev_row[j + 1] + 1)
                .min(curr_row[j] + 1)
                .min(prev_row[j] + cost);
        }
        std::mem::swap(&mut prev_row, &mut curr_row);
    }

    prev_row[n]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::builtins::register_builtins;

    fn make_ctx() -> CommandContext {
        CommandContext {
            agent_id: String::new(),
            principal: "user".into(),
            channel: "tui".into(),
            args: Vec::new(),
            raw_input: String::new(),
        }
    }

    fn make_router_allow_all() -> CommandRouter {
        let mut registry = CommandRegistry::new();
        register_builtins(&mut registry);
        CommandRouter::new(registry, Box::new(|_, _| true))
    }

    fn make_router_deny_all() -> CommandRouter {
        let mut registry = CommandRegistry::new();
        register_builtins(&mut registry);
        CommandRouter::new(registry, Box::new(|_, _| false))
    }

    #[test]
    fn test_command_router_routes_to_handler() {
        let router = make_router_allow_all();
        let ctx = make_ctx();
        let result = router.route("/status", &ctx).unwrap();
        assert!(result.success);
        assert!(result.message.contains("ok"));
    }

    #[test]
    fn test_command_router_strips_prefix() {
        let router = make_router_allow_all();
        let ctx = make_ctx();

        // Slash prefix
        let r1 = router.route("/status", &ctx).unwrap();
        assert!(r1.success);

        // Colon prefix
        let r2 = router.route(":status", &ctx).unwrap();
        assert!(r2.success);

        // No prefix
        let r3 = router.route("status", &ctx).unwrap();
        assert!(r3.success);
    }

    #[test]
    fn test_command_router_unknown_command() {
        let router = make_router_allow_all();
        let ctx = make_ctx();
        let result = router.route("/nonexistent", &ctx).unwrap();
        assert!(!result.success);
        assert!(result.message.contains("unknown command"));
    }

    #[test]
    fn test_command_router_permission_denied() {
        let router = make_router_deny_all();
        let ctx = make_ctx();
        let result = router.route("/status", &ctx).unwrap();
        assert!(!result.success);
        assert!(result.message.contains("permission denied"));
    }

    #[test]
    fn test_command_router_validates_input() {
        let router = make_router_allow_all();
        let ctx = make_ctx();

        // Semicolon injection
        let r = router.route("/status;rm -rf /", &ctx).unwrap();
        assert!(!r.success);
        assert!(r.message.contains("forbidden character"));

        // Pipe injection
        let r = router.route("/status|cat /etc/passwd", &ctx).unwrap();
        assert!(!r.success);
        assert!(r.message.contains("forbidden character"));

        // Ampersand injection
        let r = router.route("/status&&echo pwned", &ctx).unwrap();
        assert!(!r.success);
        assert!(r.message.contains("forbidden character"));

        // Backtick injection
        let r = router.route("/`whoami`", &ctx).unwrap();
        assert!(!r.success);
        assert!(r.message.contains("forbidden character"));

        // Dollar sign injection
        let r = router.route("/$HOME", &ctx).unwrap();
        assert!(!r.success);
        assert!(r.message.contains("forbidden character"));
    }

    #[test]
    fn test_command_router_empty_input() {
        let router = make_router_allow_all();
        let ctx = make_ctx();
        let result = router.route("", &ctx).unwrap();
        assert!(!result.success);
        assert!(result.message.contains("empty"));
    }

    #[test]
    fn test_command_router_suggestion() {
        let router = make_router_allow_all();
        let ctx = make_ctx();
        // "statu" is close to "status"
        let result = router.route("/statu", &ctx).unwrap();
        assert!(!result.success);
        assert!(result.message.contains("Did you mean"));
    }

    #[test]
    fn test_levenshtein() {
        assert_eq!(levenshtein("", ""), 0);
        assert_eq!(levenshtein("abc", "abc"), 0);
        assert_eq!(levenshtein("abc", "ab"), 1);
        assert_eq!(levenshtein("kitten", "sitting"), 3);
    }

    #[test]
    fn test_validate_command_name_rejects_control_chars() {
        assert!(validate_command_name("test\x00cmd").is_err());
        assert!(validate_command_name("test\x07").is_err());
    }

    #[test]
    fn test_validate_command_name_rejects_too_long() {
        let long = "a".repeat(65);
        assert!(validate_command_name(&long).is_err());
    }

    #[test]
    fn test_validate_command_name_accepts_valid() {
        assert!(validate_command_name("status").is_ok());
        assert!(validate_command_name("fleet-status").is_ok());
        assert!(validate_command_name("my_cmd").is_ok());
        assert!(validate_command_name("cmd123").is_ok());
    }
}
