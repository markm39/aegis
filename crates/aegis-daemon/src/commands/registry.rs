//! Command registry: stores and looks up [`CommandDef`] implementations.
//!
//! Commands are registered by their primary name and all aliases. Lookups are
//! case-insensitive to support both TUI (`:Status`) and Telegram (`/status`)
//! conventions. The `list()` method deduplicates aliases so each command
//! appears exactly once.

use std::collections::HashMap;
use std::sync::Arc;

use super::handler::CommandDef;

/// Registry of command definitions, keyed by name and aliases.
///
/// Internally, every name (primary + aliases) maps to the same `Arc<dyn CommandDef>`.
/// Lookups are case-insensitive. The `list()` method returns each command once,
/// sorted by primary name.
pub struct CommandRegistry {
    /// Map from lowercase name/alias to command definition.
    commands: HashMap<String, Arc<dyn CommandDef>>,
    /// Set of primary command names (lowercase) for deduplication in `list()`.
    primary_names: Vec<String>,
}

impl CommandRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            commands: HashMap::new(),
            primary_names: Vec::new(),
        }
    }

    /// Register a command by its primary name and all aliases.
    ///
    /// Overwrites any previous registration for the same names.
    pub fn register(&mut self, cmd: Box<dyn CommandDef>) {
        let arc: Arc<dyn CommandDef> = Arc::from(cmd);
        let primary = arc.name().to_lowercase();

        self.commands.insert(primary.clone(), Arc::clone(&arc));
        self.primary_names.push(primary);

        for alias in arc.aliases() {
            self.commands.insert(alias.to_lowercase(), Arc::clone(&arc));
        }
    }

    /// Look up a command by name or alias (case-insensitive).
    pub fn lookup(&self, name: &str) -> Option<Arc<dyn CommandDef>> {
        self.commands.get(&name.to_lowercase()).cloned()
    }

    /// Return all unique commands (deduplicated by primary name), sorted alphabetically.
    pub fn list(&self) -> Vec<Arc<dyn CommandDef>> {
        let mut seen = Vec::new();
        let mut result = Vec::new();

        for name in &self.primary_names {
            if seen.contains(name) {
                continue;
            }
            if let Some(cmd) = self.commands.get(name) {
                seen.push(name.clone());
                result.push(Arc::clone(cmd));
            }
        }

        result.sort_by(|a, b| a.name().cmp(b.name()));
        result
    }

    /// Return formatted help text for a specific command, or `None` if not found.
    pub fn lookup_help(&self, name: &str) -> Option<String> {
        let cmd = self.lookup(name)?;
        let aliases = cmd.aliases();
        let alias_str = if aliases.is_empty() {
            String::new()
        } else {
            format!(" (aliases: {})", aliases.join(", "))
        };
        Some(format!(
            "{}{}\n  {}\n  Usage: {}",
            cmd.name(),
            alias_str,
            cmd.description(),
            cmd.usage(),
        ))
    }

    /// Return all registered names (primary + aliases) for suggestion matching.
    pub fn all_names(&self) -> Vec<String> {
        self.commands.keys().cloned().collect()
    }
}

impl Default for CommandRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::handler::{CommandContext, CommandResult};
    use anyhow::Result;

    struct TestCmd;
    impl CommandDef for TestCmd {
        fn name(&self) -> &str {
            "test"
        }
        fn aliases(&self) -> Vec<&str> {
            vec!["t", "tst"]
        }
        fn description(&self) -> &str {
            "A test command"
        }
        fn usage(&self) -> &str {
            "test [arg]"
        }
        fn required_action(&self) -> &str {
            "ToolCall"
        }
        fn execute(&self, _ctx: &CommandContext) -> Result<CommandResult> {
            Ok(CommandResult::ok("test ok"))
        }
    }

    struct AnotherCmd;
    impl CommandDef for AnotherCmd {
        fn name(&self) -> &str {
            "another"
        }
        fn description(&self) -> &str {
            "Another command"
        }
        fn usage(&self) -> &str {
            "another"
        }
        fn required_action(&self) -> &str {
            "ToolCall"
        }
        fn execute(&self, _ctx: &CommandContext) -> Result<CommandResult> {
            Ok(CommandResult::ok("another ok"))
        }
    }

    #[test]
    fn test_command_registry_register_and_lookup() {
        let mut reg = CommandRegistry::new();
        reg.register(Box::new(TestCmd));

        // Lookup by primary name
        let cmd = reg.lookup("test");
        assert!(cmd.is_some());
        assert_eq!(cmd.unwrap().name(), "test");

        // Lookup by alias
        let cmd = reg.lookup("t");
        assert!(cmd.is_some());
        assert_eq!(cmd.unwrap().name(), "test");

        let cmd = reg.lookup("tst");
        assert!(cmd.is_some());
        assert_eq!(cmd.unwrap().name(), "test");

        // Lookup unknown
        assert!(reg.lookup("nonexistent").is_none());
    }

    #[test]
    fn test_command_registry_case_insensitive_lookup() {
        let mut reg = CommandRegistry::new();
        reg.register(Box::new(TestCmd));

        assert!(reg.lookup("TEST").is_some());
        assert!(reg.lookup("Test").is_some());
        assert!(reg.lookup("T").is_some());
        assert!(reg.lookup("TST").is_some());
    }

    #[test]
    fn test_command_registry_list_deduplicates() {
        let mut reg = CommandRegistry::new();
        reg.register(Box::new(TestCmd));
        reg.register(Box::new(AnotherCmd));

        let list = reg.list();
        // Should have exactly 2 commands, not 4 (test has 2 aliases)
        assert_eq!(list.len(), 2);

        let names: Vec<&str> = list.iter().map(|c| c.name()).collect();
        assert!(names.contains(&"another"));
        assert!(names.contains(&"test"));
    }

    #[test]
    fn test_command_registry_lookup_help() {
        let mut reg = CommandRegistry::new();
        reg.register(Box::new(TestCmd));

        let help = reg.lookup_help("test").unwrap();
        assert!(help.contains("test"));
        assert!(help.contains("t, tst"));
        assert!(help.contains("A test command"));
        assert!(help.contains("test [arg]"));

        assert!(reg.lookup_help("nonexistent").is_none());
    }
}
