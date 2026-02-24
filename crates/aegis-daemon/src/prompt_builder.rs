//! Fluent system prompt builder for agent initialization.
//!
//! Constructs structured system prompts from agent context fields,
//! fleet goals, and memory entries.

/// A section of a system prompt with a heading and content body.
struct PromptSection {
    heading: String,
    content: String,
}

/// Fluent builder for constructing structured system prompts.
///
/// Sections are appended in the order they are added and rendered
/// as markdown with `## Heading` followed by the content.
///
/// # Example
///
/// ```
/// use aegis_daemon::prompt_builder::PromptBuilder;
///
/// let prompt = PromptBuilder::new()
///     .role("Backend engineer")
///     .goal("Implement the REST API")
///     .task("Add the /users endpoint")
///     .build();
///
/// assert!(prompt.contains("## Role"));
/// assert!(prompt.contains("Backend engineer"));
/// ```
pub struct PromptBuilder {
    sections: Vec<PromptSection>,
}

impl PromptBuilder {
    /// Create a new empty prompt builder.
    pub fn new() -> Self {
        Self {
            sections: Vec::new(),
        }
    }

    /// Add a "Role" section describing the agent's role.
    pub fn role(mut self, role: &str) -> Self {
        self.sections.push(PromptSection {
            heading: "Role".into(),
            content: role.into(),
        });
        self
    }

    /// Add a "Goal" section describing the agent's strategic goal.
    pub fn goal(mut self, goal: &str) -> Self {
        self.sections.push(PromptSection {
            heading: "Goal".into(),
            content: goal.into(),
        });
        self
    }

    /// Add a "Context" section with additional constraints or knowledge.
    pub fn context(mut self, context: &str) -> Self {
        self.sections.push(PromptSection {
            heading: "Context".into(),
            content: context.into(),
        });
        self
    }

    /// Add a "Task" section with the current task or prompt.
    pub fn task(mut self, task: &str) -> Self {
        self.sections.push(PromptSection {
            heading: "Task".into(),
            content: task.into(),
        });
        self
    }

    /// Add a "Memory" section from key-value memory entries.
    ///
    /// Each entry is rendered as a bullet: `- **key**: value`.
    /// If entries is empty, no section is added.
    pub fn memory(mut self, entries: &[(String, String)]) -> Self {
        if entries.is_empty() {
            return self;
        }

        let lines: Vec<String> = entries
            .iter()
            .map(|(k, v)| format!("- **{k}**: {v}"))
            .collect();

        self.sections.push(PromptSection {
            heading: "Memory".into(),
            content: lines.join("\n"),
        });
        self
    }

    /// Add a "Fleet Goal" section with the fleet-wide mission.
    pub fn fleet_goal(mut self, goal: &str) -> Self {
        self.sections.push(PromptSection {
            heading: "Fleet Goal".into(),
            content: goal.into(),
        });
        self
    }

    /// Add a custom section with an arbitrary heading and content.
    pub fn custom_section(mut self, heading: &str, content: &str) -> Self {
        self.sections.push(PromptSection {
            heading: heading.into(),
            content: content.into(),
        });
        self
    }

    /// Build the final prompt string.
    ///
    /// Sections are joined with double newlines and rendered as markdown:
    /// ```text
    /// ## Role
    /// Backend engineer
    ///
    /// ## Goal
    /// Implement the REST API
    /// ```
    pub fn build(self) -> String {
        self.sections
            .iter()
            .map(|s| format!("## {}\n{}", s.heading, s.content))
            .collect::<Vec<_>>()
            .join("\n\n")
    }
}

impl Default for PromptBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_with_all_fields() {
        let prompt = PromptBuilder::new()
            .role("Backend engineer")
            .goal("Build the API")
            .context("Use Rust and Axum framework")
            .task("Implement /users endpoint")
            .memory(&[
                ("last_commit".into(), "abc123".into()),
                ("status".into(), "in progress".into()),
            ])
            .fleet_goal("Ship v2.0 by Friday")
            .build();

        assert!(prompt.contains("## Role\nBackend engineer"));
        assert!(prompt.contains("## Goal\nBuild the API"));
        assert!(prompt.contains("## Context\nUse Rust and Axum framework"));
        assert!(prompt.contains("## Task\nImplement /users endpoint"));
        assert!(prompt.contains("## Memory\n- **last_commit**: abc123\n- **status**: in progress"));
        assert!(prompt.contains("## Fleet Goal\nShip v2.0 by Friday"));
    }

    #[test]
    fn build_with_partial_fields() {
        let prompt = PromptBuilder::new()
            .role("Frontend dev")
            .task("Fix the login page")
            .build();

        assert!(prompt.contains("## Role\nFrontend dev"));
        assert!(prompt.contains("## Task\nFix the login page"));
        assert!(!prompt.contains("## Goal"));
        assert!(!prompt.contains("## Context"));
        assert!(!prompt.contains("## Memory"));
        assert!(!prompt.contains("## Fleet Goal"));
    }

    #[test]
    fn empty_builder() {
        let prompt = PromptBuilder::new().build();
        assert!(prompt.is_empty());
    }

    #[test]
    fn section_ordering() {
        let prompt = PromptBuilder::new()
            .task("first")
            .role("second")
            .goal("third")
            .build();

        let task_pos = prompt.find("## Task").unwrap();
        let role_pos = prompt.find("## Role").unwrap();
        let goal_pos = prompt.find("## Goal").unwrap();

        // Sections appear in the order they were added.
        assert!(task_pos < role_pos);
        assert!(role_pos < goal_pos);
    }

    #[test]
    fn custom_section() {
        let prompt = PromptBuilder::new()
            .role("Tester")
            .custom_section("Rules", "Never delete production data")
            .build();

        assert!(prompt.contains("## Rules\nNever delete production data"));
    }

    #[test]
    fn memory_skips_empty() {
        let prompt = PromptBuilder::new().role("Agent").memory(&[]).build();

        assert!(!prompt.contains("## Memory"));
    }

    #[test]
    fn default_builder_is_empty() {
        let prompt = PromptBuilder::default().build();
        assert!(prompt.is_empty());
    }
}
