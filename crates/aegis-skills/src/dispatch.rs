//! Slash command dispatch -- parsing, routing, and execution of `/command` inputs.
//!
//! Provides:
//! - [`SlashCommand`] -- a parsed slash command with name, args, and source
//! - [`CommandSource`] -- where the command originated (CLI, TUI, Telegram, etc.)
//! - [`parse_slash_command`] -- parses raw input like `/search rust async` into a command
//! - [`CommandRouter`] -- maps command names to skills, with alias support
//! - [`dispatch`] -- end-to-end: parse command, find skill, execute, return output

use std::collections::HashMap;

use anyhow::{Context, Result};

use crate::executor::SkillExecutor;
use crate::manifest::SkillManifest;
use crate::registry::SkillRegistry;
use crate::sdk::{SkillContext, SkillOutput};

/// Where a slash command originated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandSource {
    /// From the CLI (e.g., `aegis /search query`).
    Cli,
    /// From the fleet TUI command bar.
    Tui,
    /// From a Telegram channel.
    Telegram,
    /// From a Slack channel.
    Slack,
    /// From a Discord channel.
    Discord,
    /// From an HTTP/WebSocket API.
    Api,
}

/// A parsed slash command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlashCommand {
    /// The command name (e.g., "search").
    pub name: String,
    /// Parsed arguments.
    pub args: Vec<String>,
    /// The original input string.
    pub raw: String,
    /// Where the command came from.
    pub source: CommandSource,
}

/// Metadata about a registered command.
#[derive(Debug, Clone)]
pub struct CommandInfo {
    /// The command name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// The skill that handles this command.
    pub skill_name: String,
    /// Aliases for this command.
    pub aliases: Vec<String>,
    /// Usage string (e.g., "/search <query>").
    pub usage: String,
}

/// Routes slash commands to skills.
///
/// Maintains a mapping of command names to skill names and supports aliases.
#[derive(Debug, Default)]
pub struct CommandRouter {
    /// command_name -> skill_name
    commands: HashMap<String, String>,
    /// alias -> canonical command_name
    aliases: HashMap<String, String>,
    /// command_name -> CommandInfo metadata
    info: HashMap<String, CommandInfo>,
}

impl CommandRouter {
    /// Create an empty router.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a command name that routes to the given skill.
    pub fn register_command(&mut self, name: &str, skill_name: &str) {
        self.commands
            .insert(name.to_string(), skill_name.to_string());
    }

    /// Register a command with full metadata.
    pub fn register_command_with_info(
        &mut self,
        name: &str,
        skill_name: &str,
        description: &str,
        usage: &str,
    ) {
        self.commands
            .insert(name.to_string(), skill_name.to_string());
        self.info.insert(
            name.to_string(),
            CommandInfo {
                name: name.to_string(),
                description: description.to_string(),
                skill_name: skill_name.to_string(),
                aliases: Vec::new(),
                usage: usage.to_string(),
            },
        );
    }

    /// Register an alias that resolves to a canonical command name.
    ///
    /// For example, alias "s" -> command "search".
    pub fn register_alias(&mut self, alias: &str, command: &str) {
        self.aliases.insert(alias.to_string(), command.to_string());
        // Update the info entry with this alias if it exists
        if let Some(info) = self.info.get_mut(command) {
            if !info.aliases.contains(&alias.to_string()) {
                info.aliases.push(alias.to_string());
            }
        }
    }

    /// Resolve a command name (or alias) to a skill name.
    ///
    /// Returns `None` if the name is not registered and not an alias.
    pub fn route(&self, command: &SlashCommand) -> Option<&str> {
        // Try direct lookup first
        if let Some(skill) = self.commands.get(&command.name) {
            return Some(skill.as_str());
        }
        // Try alias resolution
        if let Some(canonical) = self.aliases.get(&command.name) {
            if let Some(skill) = self.commands.get(canonical) {
                return Some(skill.as_str());
            }
        }
        None
    }

    /// Resolve a command name string (or alias) to a skill name.
    pub fn route_name(&self, name: &str) -> Option<&str> {
        if let Some(skill) = self.commands.get(name) {
            return Some(skill.as_str());
        }
        if let Some(canonical) = self.aliases.get(name) {
            if let Some(skill) = self.commands.get(canonical) {
                return Some(skill.as_str());
            }
        }
        None
    }

    /// List all registered commands with their metadata.
    pub fn list_commands(&self) -> Vec<CommandInfo> {
        let mut result: Vec<CommandInfo> = self
            .commands
            .iter()
            .map(|(name, skill_name)| {
                if let Some(info) = self.info.get(name) {
                    info.clone()
                } else {
                    CommandInfo {
                        name: name.clone(),
                        description: String::new(),
                        skill_name: skill_name.clone(),
                        aliases: self
                            .aliases
                            .iter()
                            .filter(|(_, cmd)| *cmd == name)
                            .map(|(alias, _)| alias.clone())
                            .collect(),
                        usage: format!("/{name}"),
                    }
                }
            })
            .collect();
        result.sort_by(|a, b| a.name.cmp(&b.name));
        result
    }

    /// Return the number of registered commands.
    pub fn command_count(&self) -> usize {
        self.commands.len()
    }

    /// Auto-register commands from a skill manifest's `commands` field.
    ///
    /// If the manifest has a `commands` section (parsed from `[[commands]]`
    /// entries in the manifest TOML), each command is registered with its
    /// metadata.
    pub fn register_from_manifest(&mut self, manifest: &SkillManifest) {
        if let Some(ref commands) = manifest.commands {
            for cmd in commands {
                self.register_command_with_info(
                    &cmd.name,
                    &manifest.name,
                    &cmd.description,
                    &cmd.usage,
                );
                for alias in &cmd.aliases {
                    self.register_alias(alias, &cmd.name);
                }
            }
        }
    }
}

/// Parse a raw input string as a slash command.
///
/// The input must start with `/`. The command name is the first token after
/// the slash. Remaining tokens are parsed as arguments, with support for
/// quoted strings (double quotes).
///
/// Returns `None` if the input is not a slash command (does not start with `/`).
///
/// # Examples
///
/// ```
/// use aegis_skills::dispatch::{parse_slash_command, CommandSource};
///
/// let cmd = parse_slash_command("/search rust async patterns", CommandSource::Cli).unwrap();
/// assert_eq!(cmd.name, "search");
/// assert_eq!(cmd.args, vec!["rust", "async", "patterns"]);
/// ```
pub fn parse_slash_command(input: &str, source: CommandSource) -> Option<SlashCommand> {
    let trimmed = input.trim();
    if !trimmed.starts_with('/') {
        return None;
    }

    let without_slash = &trimmed[1..];
    if without_slash.is_empty() {
        return None;
    }

    let args = parse_args(without_slash);
    if args.is_empty() {
        return None;
    }

    let name = args[0].clone();
    let command_args = args[1..].to_vec();

    Some(SlashCommand {
        name,
        args: command_args,
        raw: trimmed.to_string(),
        source,
    })
}

/// Parse an argument string into tokens, respecting double-quoted strings.
///
/// Quoted strings preserve internal whitespace and are unescaped:
/// - `\"` inside quotes becomes `"`
/// - Unmatched trailing quotes consume the rest as a single token
fn parse_args(input: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut chars = input.chars().peekable();
    let mut current = String::new();

    while let Some(&ch) = chars.peek() {
        match ch {
            ' ' | '\t' => {
                if !current.is_empty() {
                    args.push(current.clone());
                    current.clear();
                }
                chars.next();
            }
            '"' => {
                chars.next(); // consume opening quote
                              // Read until closing quote
                loop {
                    match chars.next() {
                        Some('\\') => {
                            // Escaped character inside quotes
                            if let Some(escaped) = chars.next() {
                                current.push(escaped);
                            }
                        }
                        Some('"') => break,
                        Some(c) => current.push(c),
                        None => break, // unterminated quote -- use what we have
                    }
                }
                // Push even if empty (empty quoted string is valid)
                args.push(current.clone());
                current.clear();
            }
            _ => {
                current.push(ch);
                chars.next();
            }
        }
    }

    if !current.is_empty() {
        args.push(current);
    }

    args
}

/// Execute a slash command through the router, registry, and executor.
///
/// 1. Looks up the skill for the command via the router
/// 2. Finds the skill instance in the registry
/// 3. Builds a `SkillInput` from the command args
/// 4. Executes via the `SkillExecutor`
/// 5. Returns the `SkillOutput`
pub async fn dispatch(
    command: &SlashCommand,
    router: &CommandRouter,
    registry: &SkillRegistry,
    executor: &SkillExecutor,
    context: SkillContext,
) -> Result<SkillOutput> {
    let skill_name = router
        .route(command)
        .ok_or_else(|| anyhow::anyhow!("no skill registered for command: /{}", command.name))?;

    let instance = registry.get(skill_name).ok_or_else(|| {
        anyhow::anyhow!(
            "skill '{}' is registered for /{} but not found in registry",
            skill_name,
            command.name
        )
    })?;

    // Build parameters from command args
    let parameters = serde_json::json!({
        "args": command.args,
        "raw": command.raw,
    });

    executor
        .execute(
            &instance.manifest,
            &instance.path,
            &command.name,
            parameters,
            context,
        )
        .await
        .with_context(|| {
            format!(
                "failed to execute /{} via skill '{}'",
                command.name, skill_name
            )
        })
}

/// A command entry declared in a skill manifest.
///
/// Parsed from `[[commands]]` entries in `manifest.toml`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ManifestCommand {
    /// The command name (e.g., "search").
    pub name: String,
    /// Human-readable description.
    #[serde(default)]
    pub description: String,
    /// Usage string (e.g., "/search <query>").
    #[serde(default)]
    pub usage: String,
    /// Short aliases for this command.
    #[serde(default)]
    pub aliases: Vec<String>,
}

/// Auto-register commands from all skills in a registry into a router.
///
/// Iterates all skills in the registry and registers any commands declared
/// in their manifests.
pub fn auto_register_commands(router: &mut CommandRouter, registry: &SkillRegistry) {
    for instance in registry.list() {
        router.register_from_manifest(&instance.manifest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::SkillInstance;
    use crate::manifest::parse_manifest;
    use std::path::PathBuf;

    #[test]
    fn parse_simple_command() {
        let cmd = parse_slash_command("/search rust async", CommandSource::Cli).unwrap();
        assert_eq!(cmd.name, "search");
        assert_eq!(cmd.args, vec!["rust", "async"]);
        assert_eq!(cmd.raw, "/search rust async");
        assert_eq!(cmd.source, CommandSource::Cli);
    }

    #[test]
    fn parse_command_no_args() {
        let cmd = parse_slash_command("/help", CommandSource::Tui).unwrap();
        assert_eq!(cmd.name, "help");
        assert!(cmd.args.is_empty());
        assert_eq!(cmd.source, CommandSource::Tui);
    }

    #[test]
    fn parse_command_with_quoted_args() {
        let cmd =
            parse_slash_command(r#"/search "rust async" patterns"#, CommandSource::Cli).unwrap();
        assert_eq!(cmd.name, "search");
        assert_eq!(cmd.args, vec!["rust async", "patterns"]);
    }

    #[test]
    fn parse_command_with_escaped_quotes() {
        let cmd = parse_slash_command(r#"/echo "say \"hello\"""#, CommandSource::Cli).unwrap();
        assert_eq!(cmd.name, "echo");
        assert_eq!(cmd.args, vec![r#"say "hello""#]);
    }

    #[test]
    fn parse_not_slash_command() {
        assert!(parse_slash_command("search rust", CommandSource::Cli).is_none());
        assert!(parse_slash_command("", CommandSource::Cli).is_none());
        assert!(parse_slash_command("  ", CommandSource::Cli).is_none());
    }

    #[test]
    fn parse_slash_only() {
        assert!(parse_slash_command("/", CommandSource::Cli).is_none());
    }

    #[test]
    fn parse_command_with_leading_whitespace() {
        let cmd = parse_slash_command("  /search query  ", CommandSource::Telegram).unwrap();
        assert_eq!(cmd.name, "search");
        assert_eq!(cmd.args, vec!["query"]);
        assert_eq!(cmd.source, CommandSource::Telegram);
    }

    #[test]
    fn parse_command_preserves_raw() {
        let cmd = parse_slash_command("/translate hello world", CommandSource::Api).unwrap();
        assert_eq!(cmd.raw, "/translate hello world");
    }

    #[test]
    fn parse_empty_quoted_string() {
        let cmd = parse_slash_command(r#"/cmd "" arg"#, CommandSource::Cli).unwrap();
        assert_eq!(cmd.args, vec!["", "arg"]);
    }

    #[test]
    fn parse_multiple_spaces_between_args() {
        let cmd = parse_slash_command("/cmd  arg1   arg2", CommandSource::Cli).unwrap();
        assert_eq!(cmd.args, vec!["arg1", "arg2"]);
    }

    #[test]
    fn router_register_and_route() {
        let mut router = CommandRouter::new();
        router.register_command("search", "web-search");
        router.register_command("calc", "calculator");

        let cmd = parse_slash_command("/search query", CommandSource::Cli).unwrap();
        assert_eq!(router.route(&cmd), Some("web-search"));

        let cmd2 = parse_slash_command("/calc 2+2", CommandSource::Cli).unwrap();
        assert_eq!(router.route(&cmd2), Some("calculator"));
    }

    #[test]
    fn router_alias() {
        let mut router = CommandRouter::new();
        router.register_command("search", "web-search");
        router.register_alias("s", "search");
        router.register_alias("find", "search");

        let cmd = parse_slash_command("/s query", CommandSource::Cli).unwrap();
        assert_eq!(router.route(&cmd), Some("web-search"));

        let cmd2 = parse_slash_command("/find query", CommandSource::Cli).unwrap();
        assert_eq!(router.route(&cmd2), Some("web-search"));
    }

    #[test]
    fn router_unknown_command() {
        let router = CommandRouter::new();
        let cmd = parse_slash_command("/nonexistent", CommandSource::Cli).unwrap();
        assert_eq!(router.route(&cmd), None);
    }

    #[test]
    fn router_route_name() {
        let mut router = CommandRouter::new();
        router.register_command("search", "web-search");
        router.register_alias("s", "search");

        assert_eq!(router.route_name("search"), Some("web-search"));
        assert_eq!(router.route_name("s"), Some("web-search"));
        assert_eq!(router.route_name("nope"), None);
    }

    #[test]
    fn router_list_commands() {
        let mut router = CommandRouter::new();
        router.register_command_with_info(
            "search",
            "web-search",
            "Search the web",
            "/search <query>",
        );
        router.register_command_with_info("calc", "calculator", "Calculate", "/calc <expr>");
        router.register_alias("s", "search");

        let commands = router.list_commands();
        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0].name, "calc");
        assert_eq!(commands[1].name, "search");
        assert_eq!(commands[1].skill_name, "web-search");
        assert!(commands[1].aliases.contains(&"s".to_string()));
    }

    #[test]
    fn router_command_count() {
        let mut router = CommandRouter::new();
        assert_eq!(router.command_count(), 0);
        router.register_command("a", "skill-a");
        assert_eq!(router.command_count(), 1);
        router.register_command("b", "skill-b");
        assert_eq!(router.command_count(), 2);
    }

    #[test]
    fn auto_register_from_manifest() {
        let toml_str = r#"
name = "web-search"
version = "1.0.0"
description = "Search the web"
entry_point = "run.sh"

[[commands]]
name = "search"
description = "Search the web"
usage = "/search <query>"
aliases = ["s", "find"]

[[commands]]
name = "lucky"
description = "I'm feeling lucky"
usage = "/lucky <query>"
aliases = []
"#;
        let manifest = parse_manifest(toml_str).unwrap();
        let mut router = CommandRouter::new();
        router.register_from_manifest(&manifest);

        assert_eq!(router.command_count(), 2);
        assert_eq!(router.route_name("search"), Some("web-search"));
        assert_eq!(router.route_name("lucky"), Some("web-search"));
        assert_eq!(router.route_name("s"), Some("web-search"));
        assert_eq!(router.route_name("find"), Some("web-search"));
    }

    #[test]
    fn auto_register_from_registry() {
        let toml_str = r#"
name = "calculator"
version = "1.0.0"
description = "Math calculator"
entry_point = "run.sh"

[[commands]]
name = "calc"
description = "Calculate expression"
usage = "/calc <expr>"
aliases = ["c"]
"#;
        let manifest = parse_manifest(toml_str).unwrap();
        let instance = SkillInstance::discover(manifest, PathBuf::from("/tmp/calculator"));
        let mut registry = SkillRegistry::new();
        registry.register(instance).unwrap();

        let mut router = CommandRouter::new();
        auto_register_commands(&mut router, &registry);

        assert_eq!(router.route_name("calc"), Some("calculator"));
        assert_eq!(router.route_name("c"), Some("calculator"));
    }

    #[test]
    fn command_source_variants() {
        // Ensure all variants are distinct
        let sources = vec![
            CommandSource::Cli,
            CommandSource::Tui,
            CommandSource::Telegram,
            CommandSource::Slack,
            CommandSource::Discord,
            CommandSource::Api,
        ];
        for (i, a) in sources.iter().enumerate() {
            for (j, b) in sources.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn command_info_from_register_with_info() {
        let mut router = CommandRouter::new();
        router.register_command_with_info(
            "translate",
            "translator",
            "Translate text between languages",
            "/translate <from> <to> <text>",
        );

        let commands = router.list_commands();
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].description, "Translate text between languages");
        assert_eq!(commands[0].usage, "/translate <from> <to> <text>");
    }

    #[test]
    fn register_alias_updates_info() {
        let mut router = CommandRouter::new();
        router.register_command_with_info("search", "web-search", "Search", "/search <q>");
        router.register_alias("s", "search");
        router.register_alias("find", "search");

        let commands = router.list_commands();
        let search = commands.iter().find(|c| c.name == "search").unwrap();
        assert!(search.aliases.contains(&"s".to_string()));
        assert!(search.aliases.contains(&"find".to_string()));
    }

    #[test]
    fn parse_unterminated_quote() {
        let cmd = parse_slash_command(r#"/cmd "unterminated"#, CommandSource::Cli).unwrap();
        assert_eq!(cmd.args, vec!["unterminated"]);
    }

    #[test]
    fn register_command_overwrite() {
        let mut router = CommandRouter::new();
        router.register_command("search", "old-search");
        router.register_command("search", "new-search");

        assert_eq!(router.route_name("search"), Some("new-search"));
    }
}
