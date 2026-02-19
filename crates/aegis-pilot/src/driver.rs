//! Agent driver trait for full lifecycle management.
//!
//! While [`AgentAdapter`](crate::adapter::AgentAdapter) handles prompt detection
//! at the I/O level, the `AgentDriver` trait handles the higher-level lifecycle:
//! how to spawn the tool, what adapter to use, how to inject tasks, and what
//! headless options are available.

use std::path::Path;

use crate::adapter::AgentAdapter;
use crate::session::ToolKind;

/// How to spawn an agent process.
#[derive(Debug, Clone)]
pub enum SpawnStrategy {
    /// Spawn in a PTY (full terminal emulation, bidirectional I/O).
    Pty {
        command: String,
        args: Vec<String>,
        env: Vec<(String, String)>,
    },
    /// Spawn as a regular process (no PTY; stdout/stderr only).
    Process {
        command: String,
        args: Vec<String>,
        env: Vec<(String, String)>,
        kind: ProcessKind,
    },
    /// Agent is already running externally (observe-only).
    External,
}

/// How to treat a non-PTY process.
#[derive(Debug, Clone)]
pub enum ProcessKind {
    /// JSONL/structured stream that can be formatted and resumed.
    Json { tool: ToolKind },
    /// Detached GUI/utility process (spawn and do not supervise).
    Detached,
}

/// How to inject a task/prompt into an agent.
#[derive(Debug, Clone)]
pub enum TaskInjection {
    /// Write text directly to the agent's stdin after spawn.
    Stdin { text: String },
    /// Pass the task as a CLI argument (agent must be spawned with this arg).
    CliArg { flag: String, value: String },
    /// No task injection (agent is autonomous or GUI-based).
    None,
}

/// Trait for managing an AI tool's full lifecycle in a daemon slot.
///
/// Each supported tool (Claude Code, Codex, OpenClaw, Cursor, Custom) has
/// a driver implementation that knows:
/// - How to construct the spawn command
/// - Which adapter to use for prompt detection
/// - How to inject initial tasks
/// - What headless/non-interactive flags are available
pub trait AgentDriver: Send {
    /// Human-readable name for this driver (e.g., "ClaudeCode").
    fn name(&self) -> &str;

    /// How to spawn the agent process.
    fn spawn_strategy(&self, working_dir: &Path) -> SpawnStrategy;

    /// Create the appropriate adapter for this tool, if any.
    ///
    /// Returns `None` for tools that don't need prompt detection (e.g., Cursor
    /// in observe-only mode). The daemon will use a PassthroughAdapter.
    fn create_adapter(&self) -> Option<Box<dyn AgentAdapter>>;

    /// How to inject a task into this agent.
    fn task_injection(&self, task: &str) -> TaskInjection;

    /// Whether this tool supports headless (non-interactive) operation.
    fn supports_headless(&self) -> bool;
}
