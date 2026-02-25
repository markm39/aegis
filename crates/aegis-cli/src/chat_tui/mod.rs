//! Chat-centric TUI for Aegis.
//!
//! Provides a conversational interface that calls LLM APIs directly via
//! `DaemonCommand::LlmComplete`, with a minimal command bar for system
//! commands. This is the default interface when `aegis` is invoked.

pub mod compaction;
pub mod event;
pub mod hooks;
pub mod markdown;
pub mod message;
pub mod persistence;
pub mod render;
pub mod streaming;
pub mod system_prompt;
mod ui;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Instant;

use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use aegis_control::daemon::{DaemonClient, DaemonCommand, DaemonResponse};
use aegis_types::llm::{LlmMessage, LlmResponse, LlmRole, LlmToolCall, StopReason};
use aegis_types::tool_classification::ActionRisk;

use self::event::{AppEvent, EventHandler};
use self::message::{ChatMessage, MessageRole};
use self::system_prompt::{PromptMode, ToolDescription};
use crate::tui_utils::delete_word_backward_pos;

/// Skill command prompts, embedded at compile time from prompts/skills/.
mod skill_prompts {
    pub const DEBUG: &str = include_str!("prompts/skills/debug.md");
    pub const DOC: &str = include_str!("prompts/skills/doc.md");
    pub const EXPLAIN: &str = include_str!("prompts/skills/explain.md");
    pub const REFACTOR: &str = include_str!("prompts/skills/refactor.md");
    pub const TEST: &str = include_str!("prompts/skills/test.md");
    pub const REVIEW: &str = include_str!("prompts/skills/review.md");
    pub const SECURITY: &str = include_str!("prompts/skills/security.md");
    pub const PERF: &str = include_str!("prompts/skills/perf.md");
    pub const PANEL_REVIEW: &str = include_str!("prompts/skills/panel_review.md");
    pub const LINK_WORKTREE: &str = include_str!("prompts/skills/link_worktree.md");
}

/// A slash command backed by a prompt template.
struct SkillCommand {
    /// Command name (what the user types after `/`).
    name: &'static str,
    /// Prompt template with `$ARGUMENTS` placeholder.
    prompt: &'static str,
    /// Whether the command requires an argument.
    needs_arg: bool,
    /// Usage hint shown when a required arg is missing.
    arg_hint: &'static str,
}

/// All available skill commands. Looked up in `execute_command()`.
const SKILL_COMMANDS: &[SkillCommand] = &[
    SkillCommand {
        name: "debug",
        prompt: skill_prompts::DEBUG,
        needs_arg: true,
        arg_hint: "Usage: /debug <error message or description>",
    },
    SkillCommand {
        name: "doc",
        prompt: skill_prompts::DOC,
        needs_arg: true,
        arg_hint: "Usage: /doc <file or area>",
    },
    SkillCommand {
        name: "explain",
        prompt: skill_prompts::EXPLAIN,
        needs_arg: true,
        arg_hint: "Usage: /explain <file, function, or concept>",
    },
    SkillCommand {
        name: "refactor",
        prompt: skill_prompts::REFACTOR,
        needs_arg: true,
        arg_hint: "Usage: /refactor <file or area>",
    },
    SkillCommand {
        name: "test",
        prompt: skill_prompts::TEST,
        needs_arg: true,
        arg_hint: "Usage: /test <file or function>",
    },
    SkillCommand {
        name: "review",
        prompt: skill_prompts::REVIEW,
        needs_arg: false,
        arg_hint: "Usage: /review [file or description]",
    },
    SkillCommand {
        name: "security",
        prompt: skill_prompts::SECURITY,
        needs_arg: true,
        arg_hint: "Usage: /security <file or area>",
    },
    SkillCommand {
        name: "perf",
        prompt: skill_prompts::PERF,
        needs_arg: true,
        arg_hint: "Usage: /perf <file or area>",
    },
    SkillCommand {
        name: "panel-review",
        prompt: skill_prompts::PANEL_REVIEW,
        needs_arg: true,
        arg_hint: "Usage: /panel-review <topic or question>",
    },
    SkillCommand {
        name: "link-worktree",
        prompt: skill_prompts::LINK_WORKTREE,
        needs_arg: true,
        arg_hint: "Usage: /link-worktree <worktree-path>",
    },
];

/// Result of a skill execution dispatched to a background thread.
struct SkillExecResult {
    /// The slash command that triggered this skill.
    command_name: String,
    /// The skill output, or an error message.
    output: Result<aegis_skills::SkillOutput, String>,
}

/// Discover skills and build a registry + command router.
///
/// Scans the bundled `skills/` directory for skill manifests, advances each
/// through the lifecycle (discover -> validate -> load -> activate), and
/// builds a `CommandRouter` from their `[[commands]]` sections.
///
/// Returns empty registry/router if no skills are found.
fn init_skills() -> (aegis_skills::SkillRegistry, aegis_skills::CommandRouter) {
    let mut registry = aegis_skills::SkillRegistry::new();
    let mut router = aegis_skills::CommandRouter::new();

    let instances = aegis_skills::discover_bundled_skills().unwrap_or_default();

    for mut instance in instances {
        // Best-effort lifecycle advancement: validate -> load -> activate.
        if instance.validate().is_err() {
            continue;
        }
        if instance.load().is_err() {
            continue;
        }
        if instance.activate().is_err() {
            continue;
        }
        let _ = registry.register(instance);
    }

    aegis_skills::auto_register_commands(&mut router, &registry);

    (registry, router)
}

/// How often to poll crossterm for events (milliseconds).
const TICK_RATE_MS: u64 = 200;

/// How often to re-check daemon connectivity (milliseconds).
const POLL_INTERVAL_MS: u128 = 2000;

/// Timeout for LLM completion requests (seconds).
/// LLM responses can take a while, so this is much longer than the default
/// 5-second DaemonClient timeout.
const LLM_TIMEOUT_SECS: u64 = 120;

/// The current input mode in the chat TUI.
#[derive(Debug, Clone, PartialEq)]
pub enum InputMode {
    /// Default: cursor in input box, typing sends to LLM.
    Chat,
    /// Escape when input empty: navigate message history.
    Scroll,
    /// `/` when input empty: command bar.
    Command,
}

/// A saved conversation state for the restore picker.
#[derive(Debug, Clone)]
pub struct ConversationSnapshot {
    /// First 60 chars of the user message that triggered this snapshot.
    pub label: String,
    /// Display messages at the time of the snapshot.
    pub messages: Vec<ChatMessage>,
    /// LLM conversation history at the time of the snapshot.
    pub conversation: Vec<LlmMessage>,
}

/// Active overlay in the chat TUI.
///
/// Overlays render on top of the main UI and capture all input until
/// dismissed. They are modal: only one overlay can be active at a time.
#[derive(Debug, Clone)]
pub enum Overlay {
    /// Model picker: filterable list of available models.
    ModelPicker {
        /// All available (model_id, display_label) pairs.
        items: Vec<(String, String)>,
        /// User-typed filter string.
        filter: String,
        /// Index of the selected item in the filtered list.
        selected: usize,
    },
    /// Session picker: list of saved conversations.
    SessionPicker {
        /// Saved conversation metadata, newest first.
        items: Vec<persistence::ConversationMeta>,
        /// Index of the selected item.
        selected: usize,
    },
    /// Settings panel: toggle options.
    Settings {
        /// Index of the selected setting.
        selected: usize,
    },
    /// Login overlay: manage provider credentials.
    Login {
        /// All provider entries for display.
        providers: Vec<LoginProviderEntry>,
        /// Index of the selected provider.
        selected: usize,
        /// If set, showing the key input sub-view for a specific provider.
        key_input: Option<LoginKeyInput>,
    },
    /// Conversation restore picker: choose a past point to roll back to.
    RestorePicker {
        /// Snapshots to display, newest first.
        snapshots: Vec<ConversationSnapshot>,
        /// Index of the currently highlighted snapshot.
        selected: usize,
    },
}

/// Entry for a provider in the login overlay.
#[derive(Debug, Clone)]
pub(crate) struct LoginProviderEntry {
    pub id: &'static str,
    pub display_name: &'static str,
    pub status_label: String,
    pub masked_key: Option<String>,
}

/// State for the API key text input sub-view.
#[derive(Debug, Clone)]
pub(crate) struct LoginKeyInput {
    pub provider_id: &'static str,
    pub display_name: &'static str,
    pub buffer: String,
    pub cursor: usize,
    pub masked: bool,
    pub error: Option<String>,
}

/// Incremental events from the agentic loop running in a background thread.
enum AgentLoopEvent {
    /// LLM returned a text response (final -- loop ended).
    Response(LlmResponse),
    /// Incremental text from a streaming LLM response.
    StreamDelta(String),
    /// LLM wants to call tools -- display them to the user.
    ToolCalls(Vec<LlmToolCall>),
    /// A tool finished executing -- display the result.
    ToolResult {
        tool_call_id: String,
        tool_name: String,
        result: String,
    },
    /// LLM needs approval for a tool before executing it.
    ToolApprovalNeeded { tool_call: LlmToolCall },
    /// An error occurred in the loop.
    Error(String),
    /// Non-fatal informational status.
    #[allow(dead_code)]
    Notice(String),
    /// The agentic loop finished (all tool calls done, final response received).
    Done,
    /// A background subagent task completed.
    SubagentComplete {
        task_id: String,
        description: String,
        result: String,
        output_file: String,
    },
}

/// Global counter for background task IDs.
static NEXT_TASK_ID: AtomicUsize = AtomicUsize::new(1);

/// Which coding CLI backend to use for subagent spawning.
#[derive(Debug, Clone, Copy, PartialEq)]
enum SubagentBackend {
    /// Claude Code CLI (`claude --dangerously-skip-permissions -p "prompt"`).
    ClaudeCode,
    /// OpenAI Codex CLI (`codex --full-auto -p "prompt"`).
    Codex,
    /// No external CLI found; fall back to nested LLM loop.
    LlmFallback,
}

/// Detect and cache the best available coding CLI. Checked via `which`.
static SUBAGENT_BACKEND: std::sync::OnceLock<SubagentBackend> = std::sync::OnceLock::new();

fn detect_subagent_backend() -> SubagentBackend {
    *SUBAGENT_BACKEND.get_or_init(|| {
        if crate::tui_utils::binary_exists("claude") {
            SubagentBackend::ClaudeCode
        } else if crate::tui_utils::binary_exists("codex") {
            SubagentBackend::Codex
        } else {
            SubagentBackend::LlmFallback
        }
    })
}

/// Tools that are auto-approved (read-only, safe operations).
const SAFE_TOOLS: &[&str] = &[
    "read_file",
    "glob_search",
    "grep_search",
    "file_search",
    "task",
];

/// Check whether a tool should be auto-approved.
fn is_safe_tool(name: &str) -> bool {
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
fn classify_tool_risk(tool_name: &str, input: &serde_json::Value) -> ActionRisk {
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
fn classify_bash_risk(input: &serde_json::Value) -> ActionRisk {
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
fn should_auto_approve_tool(
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
fn approval_profile_label(profile: &ApprovalProfile) -> &'static str {
    match profile {
        ApprovalProfile::Manual => "manual",
        ApprovalProfile::AutoApprove(ActionRisk::Medium) => "auto-edits",
        ApprovalProfile::AutoApprove(ActionRisk::High) => "auto-high",
        ApprovalProfile::AutoApprove(_) => "auto-custom",
        ApprovalProfile::FullAuto => "full-auto",
    }
}

/// Parse an approval mode string into an `ApprovalProfile`.
///
/// Accepts: "off", "manual", "edits", "high", "full"
fn parse_approval_mode(mode: &str) -> ApprovalProfile {
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
fn approval_context_for_prompt(profile: &ApprovalProfile) -> &'static str {
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

#[allow(dead_code)]
fn latest_user_turn(conversation: &[LlmMessage]) -> Option<&str> {
    conversation
        .iter()
        .rev()
        .find(|m| m.role == aegis_types::llm::LlmRole::User)
        .map(|m| m.content.as_str())
}



/// Seed workspace with bootstrap template files if they don't exist.
///
/// Writes SOUL.md, IDENTITY.md, USER.md, TOOLS.md, and BOOTSTRAP.md to
/// `~/.aegis/workspace/`. Returns `true` if BOOTSTRAP.md was just created
/// (indicates first run -- the bootstrap conversation should be triggered).
fn seed_workspace() -> bool {
    let dir = aegis_types::daemon::workspace_dir();
    let _ = std::fs::create_dir_all(&dir);

    let templates: &[(&str, &str)] = &[
        ("BOOTSTRAP.md", include_str!("templates/BOOTSTRAP.md")),
        ("SOUL.md", include_str!("templates/SOUL.md")),
        ("IDENTITY.md", include_str!("templates/IDENTITY.md")),
        ("USER.md", include_str!("templates/USER.md")),
        ("TOOLS.md", include_str!("templates/TOOLS.md")),
        ("MEMORY.md", include_str!("templates/MEMORY.md")),
        ("HEARTBEAT.md", include_str!("templates/HEARTBEAT.md")),
    ];

    let mut is_first_run = false;
    for (name, content) in templates {
        let path = dir.join(name);
        if !path.exists() {
            let _ = std::fs::write(&path, content);
            if *name == "BOOTSTRAP.md" {
                is_first_run = true;
            }
        }
    }
    is_first_run
}

/// Top-level application state for the chat TUI.
pub struct ChatApp {
    /// Whether the main loop should keep running.
    pub running: bool,
    /// Current input mode.
    pub input_mode: InputMode,
    /// Active overlay (modal popup), if any.
    pub overlay: Option<Overlay>,

    // -- Chat --
    /// Display messages for the chat area.
    pub messages: Vec<ChatMessage>,
    /// Scroll offset into the message history (0 = bottom), in visual lines.
    pub scroll_offset: usize,
    /// Total visual lines in the chat area (updated each frame by the renderer).
    pub total_visual_lines: usize,

    // -- Session persistence --
    /// Unique identifier for this conversation session.
    pub session_id: String,
    /// Audit ledger session UUID, obtained from daemon on connect.
    /// Used to link tool execution audit entries to this chat session.
    pub audit_session_id: Option<String>,

    // -- LLM conversation --
    /// Full LLM conversation history (sent with each request).
    pub conversation: Vec<LlmMessage>,
    /// Model identifier (from daemon config or environment detection).
    pub model: String,
    /// Whether we're waiting for an LLM response or tool execution.
    pub awaiting_response: bool,
    /// Channel for receiving agentic loop events from background thread.
    agent_rx: Option<mpsc::Receiver<AgentLoopEvent>>,
    /// Channel for sending approval decisions to the background thread.
    approval_tx: Option<mpsc::Sender<bool>>,
    /// Whether we're waiting for user approval on a tool.
    pub awaiting_approval: bool,
    /// Description of the tool awaiting approval (for display).
    pub pending_tool_desc: Option<String>,
    /// Whether to auto-approve all remaining tools in this turn.
    pub auto_approve_turn: bool,
    /// Approval profile controlling risk-based auto-approval.
    pub approval_profile: ApprovalProfile,
    /// Extended thinking budget in tokens (Anthropic only). None = disabled.
    pub thinking_budget: Option<u32>,
    /// Whether a bootstrap conversation should be auto-triggered on first connect.
    pub bootstrap_pending: bool,
    /// Abort flag shared with the background agent loop thread.
    /// Setting this to `true` causes the loop to stop at the next check point.
    abort_flag: Arc<AtomicBool>,

    // -- Input --
    /// Text buffer for chat input.
    pub input_buffer: String,
    /// Cursor position in the input buffer.
    pub input_cursor: usize,
    /// History of sent inputs.
    pub input_history: Vec<String>,
    /// Current position in input history (None = composing new).
    pub history_index: Option<usize>,
    /// Saved draft buffer before navigating into input history.
    pub input_draft: String,
    /// Timestamp of the last Escape keypress (for double-Esc detection).
    pub last_esc_at: Option<std::time::Instant>,
    /// Conversation snapshots for the restore picker (taken after each assistant turn).
    pub snapshots: Vec<ConversationSnapshot>,

    // -- Command bar --
    /// Text buffer for the command bar.
    pub command_buffer: String,
    /// Cursor position in the command buffer.
    pub command_cursor: usize,
    /// History of executed commands.
    pub command_history: Vec<String>,
    /// Current position in command history.
    pub command_history_index: Option<usize>,
    /// Current tab completions.
    pub command_completions: Vec<String>,
    /// Selected completion index.
    pub completion_idx: Option<usize>,
    /// Result/error message from last command execution.
    pub command_result: Option<String>,
    /// When the command result was set (for auto-clear).
    pub command_result_at: Option<Instant>,

    // -- Usage tracking --
    /// Cumulative input tokens this session.
    pub total_input_tokens: u64,
    /// Cumulative output tokens this session.
    pub total_output_tokens: u64,
    /// Cumulative estimated cost in USD this session.
    pub total_cost_usd: f64,
    /// Whether to show usage info in the status bar.
    pub show_usage: bool,

    // -- Connection --
    /// Whether the last daemon poll succeeded.
    pub connected: bool,
    /// Last error message from daemon communication.
    pub last_error: Option<String>,

    // -- Internal --
    /// Daemon client for sending commands.
    client: Option<DaemonClient>,
    /// When we last polled the daemon.
    last_poll: Instant,
    /// Pricing table for cost calculation.
    pricing: aegis_proxy::pricing::PricingTable,

    // -- Skills --
    /// Registry of discovered and activated skills.
    skill_registry: aegis_skills::SkillRegistry,
    /// Router mapping slash command names to skills.
    skill_router: aegis_skills::CommandRouter,
    /// Dynamic command names from discovered skills (for tab completion).
    skill_command_names: Vec<String>,
    /// Channel for receiving skill execution results from background thread.
    skill_result_rx: Option<mpsc::Receiver<SkillExecResult>>,
}

/// Commands recognized by the minimal command bar.
const COMMANDS: &[&str] = &[
    "quit",
    "q",
    "clear",
    "new",
    "compact",
    "abort",
    "model",
    "provider",
    "help",
    "usage",
    "think",
    "think off",
    "think low",
    "think medium",
    "think high",
    "auto",
    "auto off",
    "auto edits",
    "auto high",
    "auto full",
    "save",
    "resume",
    "sessions",
    "settings",
    "daemon start",
    "daemon stop",
    "daemon status",
    "daemon restart",
    "daemon reload",
    "daemon init",
    // Skill commands
    "debug",
    "doc",
    "explain",
    "refactor",
    "test",
    "review",
    "security",
    "perf",
    "panel-review",
    "link-worktree",
    "login",
];

impl ChatApp {
    /// Create a new chat TUI application.
    pub fn new(client: Option<DaemonClient>, model: String) -> Self {
        let (skill_registry, skill_router) = init_skills();
        let skill_command_names: Vec<String> = skill_router
            .list_commands()
            .into_iter()
            .map(|ci| ci.name.clone())
            .collect();

        Self {
            running: true,
            input_mode: InputMode::Chat,
            overlay: None,

            messages: Vec::new(),
            scroll_offset: 0,
            total_visual_lines: 0,

            session_id: persistence::generate_conversation_id(),
            audit_session_id: None,

            conversation: Vec::new(),
            model,
            awaiting_response: false,
            agent_rx: None,
            approval_tx: None,
            awaiting_approval: false,
            pending_tool_desc: None,
            auto_approve_turn: false,
            approval_profile: ApprovalProfile::Manual,
            thinking_budget: None,
            bootstrap_pending: false,
            abort_flag: Arc::new(AtomicBool::new(false)),

            input_buffer: String::new(),
            input_cursor: 0,
            input_history: Vec::new(),
            history_index: None,
            input_draft: String::new(),
            last_esc_at: None,
            snapshots: Vec::new(),

            command_buffer: String::new(),
            command_cursor: 0,
            command_history: Vec::new(),
            command_history_index: None,
            command_completions: Vec::new(),
            completion_idx: None,
            command_result: None,
            command_result_at: None,

            total_input_tokens: 0,
            total_output_tokens: 0,
            total_cost_usd: 0.0,
            show_usage: true,

            connected: false,
            last_error: None,

            client,
            // Force immediate first poll.
            last_poll: Instant::now() - std::time::Duration::from_secs(10),
            pricing: aegis_proxy::pricing::PricingTable::with_defaults(),

            skill_registry,
            skill_router,
            skill_command_names,
            skill_result_rx: None,
        }
    }

    /// Clear stale command result messages after timeout.
    fn clear_stale_result(&mut self) {
        if let Some(at) = self.command_result_at {
            if at.elapsed().as_secs() >= 5 {
                self.command_result = None;
                self.command_result_at = None;
            }
        }
    }

    /// Poll the daemon for connectivity and check for LLM responses.
    pub fn poll_daemon(&mut self) {
        self.clear_stale_result();
        self.poll_llm();
        self.poll_skills();

        if self.last_poll.elapsed().as_millis() < POLL_INTERVAL_MS {
            return;
        }
        self.last_poll = Instant::now();

        let client = match &self.client {
            Some(c) => c,
            None => {
                self.connected = false;
                self.last_error = Some("no daemon client configured".into());
                return;
            }
        };

        // Ping
        match client.send(&DaemonCommand::Ping) {
            Ok(resp) if resp.ok => {
                let was_disconnected = !self.connected;
                self.connected = true;
                self.last_error = None;

                // Register an audit session on first connect (or reconnect).
                if was_disconnected && self.audit_session_id.is_none() {
                    self.register_audit_session();
                }

                // Trigger bootstrap conversation on first connect if this is a fresh workspace.
                if was_disconnected && self.bootstrap_pending {
                    self.bootstrap_pending = false;
                    self.trigger_bootstrap();
                }
            }
            Ok(resp) => {
                self.connected = false;
                self.last_error = Some(resp.message);
            }
            Err(e) => {
                self.connected = false;
                self.last_error = Some(e);
            }
        }
    }

    /// Register an audit session in the daemon's audit ledger.
    ///
    /// Sends `RegisterChatSession` and stores the returned UUID so
    /// subsequent tool executions are linked in the audit trail.
    fn register_audit_session(&mut self) {
        let client = match &self.client {
            Some(c) => c,
            None => return,
        };
        match client.send(&DaemonCommand::RegisterChatSession) {
            Ok(resp) if resp.ok => {
                if let Some(data) = &resp.data {
                    if let Some(sid) = data.get("session_id").and_then(|v| v.as_str()) {
                        self.audit_session_id = Some(sid.to_string());
                    }
                }
            }
            _ => {
                // Non-fatal: audit linkage is best-effort.
                // Tool execution still works; entries just won't have session linkage.
            }
        }
    }

    /// Check for events from the agentic loop running in a background thread.
    fn poll_llm(&mut self) {
        // Drain all available events from the channel.
        while let Some(rx) = self.agent_rx.as_ref() {
            let event = match rx.try_recv() {
                Ok(event) => event,
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    // Background thread died without sending Done.
                    if self.awaiting_response {
                        self.messages.push(ChatMessage::new(
                            MessageRole::System,
                            "Error: background request terminated unexpectedly."
                                .to_string(),
                        ));
                        self.awaiting_response = false;
                        self.auto_approve_turn = false;
                        self.pending_tool_desc = None;
                    }
                    self.agent_rx = None;
                    break;
                }
            };

            match event {
                AgentLoopEvent::Response(resp) => {
                    // Track usage.
                    self.total_input_tokens += resp.usage.input_tokens;
                    self.total_output_tokens += resp.usage.output_tokens;
                    if let Some(cost) = self.pricing.calculate_cost(
                        &resp.model,
                        resp.usage.input_tokens,
                        resp.usage.output_tokens,
                        0,
                        0,
                    ) {
                        self.total_cost_usd += cost;
                    }

                    // Build assistant message with tool calls if present.
                    let mut assistant_msg = LlmMessage::assistant(resp.content.clone());
                    assistant_msg.tool_calls = resp.tool_calls.clone();
                    self.conversation.push(assistant_msg);

                    // If we were streaming, the display message already exists.
                    // Only create a new display message if we weren't streaming.
                    if !resp.content.is_empty() {
                        let already_streaming = self
                            .messages
                            .last()
                            .is_some_and(|m| m.role == MessageRole::Assistant);
                        if !already_streaming {
                            self.messages
                                .push(ChatMessage::new(MessageRole::Assistant, resp.content));
                        }
                    }
                    self.scroll_offset = 0;
                }
                AgentLoopEvent::StreamDelta(text) => {
                    // Append to the current assistant message, or create one.
                    let is_assistant = self
                        .messages
                        .last()
                        .is_some_and(|m| m.role == MessageRole::Assistant);
                    if is_assistant {
                        if let Some(msg) = self.messages.last_mut() {
                            msg.content.push_str(&text);
                        }
                    } else {
                        self.messages
                            .push(ChatMessage::new(MessageRole::Assistant, text));
                    }
                    self.scroll_offset = 0;
                }
                AgentLoopEvent::ToolCalls(tool_calls) => {
                    for tc in &tool_calls {
                        let summary = summarize_tool_input(&tc.name, &tc.input);
                        self.messages.push(ChatMessage::new(
                            MessageRole::ToolCall {
                                tool_name: tc.name.clone(),
                                summary,
                            },
                            format_tool_call_content(&tc.name, &tc.input),
                        ));
                    }
                    self.scroll_offset = 0;
                }
                AgentLoopEvent::ToolResult {
                    tool_call_id,
                    tool_name,
                    result,
                } => {
                    // Add tool result to conversation.
                    self.conversation
                        .push(LlmMessage::tool_result(tool_call_id, result.clone()));
                    // Show abbreviated result in UI.
                    let display = if result.len() > 500 {
                        format!("{}...[truncated]", &result[..500])
                    } else {
                        result
                    };
                    self.messages.push(ChatMessage::new(
                        MessageRole::System,
                        format!("[{tool_name}] {display}"),
                    ));
                    self.scroll_offset = 0;
                }
                AgentLoopEvent::ToolApprovalNeeded { tool_call, .. } => {
                    let desc = format!(
                        "{}: {}",
                        tool_call.name,
                        summarize_tool_input(&tool_call.name, &tool_call.input)
                    );
                    let diff_preview =
                        generate_diff_preview(&tool_call.name, &tool_call.input);
                    self.messages.push(ChatMessage::new(
                        MessageRole::Permission {
                            prompt: desc.clone(),
                            resolved: None,
                            diff_preview,
                        },
                        format!("Allow {}? [y]es / [n]o / [a]ll", tool_call.name),
                    ));
                    self.pending_tool_desc = Some(desc);
                    self.awaiting_approval = true;
                    self.scroll_offset = 0;
                }
                AgentLoopEvent::Error(msg) => {
                    self.messages.push(ChatMessage::new(
                        MessageRole::System,
                        format!("Error: {msg}"),
                    ));
                    self.awaiting_response = false;
                    self.auto_approve_turn = false;
                }
                AgentLoopEvent::Notice(msg) => {
                    self.messages
                        .push(ChatMessage::new(MessageRole::System, msg));
                    self.scroll_offset = 0;
                }
                AgentLoopEvent::Done => {
                    self.awaiting_response = false;
                    self.auto_approve_turn = false;
                    // Save a restore point after each completed assistant turn.
                    self.push_snapshot();
                }
                AgentLoopEvent::SubagentComplete {
                    task_id,
                    description,
                    result,
                    output_file,
                } => {
                    let summary = if result.len() > 300 {
                        format!("{}...", &result[..300])
                    } else {
                        result
                    };
                    self.messages.push(ChatMessage::new(
                        MessageRole::Result {
                            summary: format!(
                                "Task \"{description}\" (id: {task_id}) completed. \
                                 Full output: {output_file}"
                            ),
                        },
                        summary,
                    ));
                    self.scroll_offset = 0;
                }
            }
        }
    }

    /// Trigger the bootstrap "getting to know you" conversation.
    ///
    /// The full bootstrap instructions are included in the system prompt
    /// (via system_prompt.rs) when BOOTSTRAP.md exists. Here we just inject
    /// a short trigger message to kick off the conversation.
    fn trigger_bootstrap(&mut self) {
        let bootstrap_path = aegis_types::daemon::workspace_dir().join("BOOTSTRAP.md");
        if !bootstrap_path.exists() {
            return;
        }

        // Short trigger -- full instructions are in the system prompt.
        self.conversation.push(LlmMessage::user(
            "[First run -- bootstrap mode active. Follow your bootstrap instructions.]"
                .to_string(),
        ));
        self.messages.push(ChatMessage::new(
            MessageRole::System,
            "Starting bootstrap -- getting to know you...".to_string(),
        ));
        self.scroll_offset = 0;
        self.awaiting_response = true;
        self.send_llm_request();
    }

    /// Send the current conversation to the LLM and run the agentic loop.
    /// Save the current conversation as a restore point.
    ///
    /// Called after each completed assistant turn. Capped at 20 snapshots;
    /// oldest are dropped when the cap is exceeded.
    fn push_snapshot(&mut self) {
        // Label: preview of the last user message that triggered this turn.
        let label = self
            .messages
            .iter()
            .rev()
            .find(|m| m.role == MessageRole::User)
            .map(|m| {
                let s = m.content.as_str();
                if s.chars().count() > 60 {
                    let end = s.char_indices().nth(60).map(|(i, _)| i).unwrap_or(s.len());
                    format!("{}…", &s[..end])
                } else {
                    s.to_string()
                }
            })
            .unwrap_or_else(|| "(empty)".to_string());

        self.snapshots.push(ConversationSnapshot {
            label,
            messages: self.messages.clone(),
            conversation: self.conversation.clone(),
        });

        // Keep at most 20 restore points.
        const MAX_SNAPSHOTS: usize = 20;
        if self.snapshots.len() > MAX_SNAPSHOTS {
            self.snapshots.drain(..self.snapshots.len() - MAX_SNAPSHOTS);
        }
    }

    ///
    /// Abort the currently running LLM request/agent loop.
    fn abort_current_request(&mut self) {
        if !self.awaiting_response && !self.awaiting_approval {
            self.set_result("Nothing to abort.");
            return;
        }
        // Signal the background thread to stop.
        self.abort_flag.store(true, Ordering::Relaxed);
        // Drop the approval channel so a blocking recv() in the agent loop unblocks.
        self.approval_tx = None;
        self.awaiting_response = false;
        self.awaiting_approval = false;
        self.pending_tool_desc = None;
        self.agent_rx = None;
        // Reset the flag for the next request.
        self.abort_flag = Arc::new(AtomicBool::new(false));

        // Inject synthetic tool_result messages for any unpaired tool_use blocks.
        // Without this, the conversation history becomes malformed and the LLM API
        // will reject subsequent requests with "tool call result does not follow
        // tool call".
        let pending_tool_ids: Vec<String> = {
            let last_assistant_idx = self
                .conversation
                .iter()
                .rposition(|m| m.role == LlmRole::Assistant && !m.tool_calls.is_empty());
            match last_assistant_idx {
                Some(idx) => {
                    let expected: Vec<String> = self.conversation[idx]
                        .tool_calls
                        .iter()
                        .map(|tc| tc.id.clone())
                        .collect();
                    // Some tool_results may already have been pushed by the
                    // background thread before the abort took effect.
                    let existing: std::collections::HashSet<&str> = self.conversation
                        [idx + 1..]
                        .iter()
                        .filter_map(|m| m.tool_use_id.as_deref())
                        .collect();
                    expected
                        .into_iter()
                        .filter(|id| !existing.contains(id.as_str()))
                        .collect()
                }
                None => vec![],
            }
        };
        for tool_id in pending_tool_ids {
            self.conversation
                .push(LlmMessage::tool_result(tool_id, "[Aborted by user]"));
        }

        self.messages.push(ChatMessage::new(
            MessageRole::System,
            "[Aborted]".to_string(),
        ));
        self.scroll_offset = 0;
    }

    /// The loop runs in a background thread. It sends the conversation + tool
    /// definitions to the LLM, and if the LLM returns `StopReason::ToolUse`,
    /// it executes each tool and loops. Tool approvals are handled via a
    /// separate mpsc channel that the UI thread sends decisions through.
    fn send_llm_request(&mut self) {
        // Auto-compact if the conversation exceeds the model's context window.
        if let Some(compacted) = compaction::compact_conversation(&self.conversation, &self.model) {
            let old_len = self.conversation.len();
            let new_len = compacted.len();
            self.conversation = compacted;
            self.messages.push(ChatMessage::new(
                MessageRole::System,
                format!(
                    "[Compacted: {} messages -> {} to fit context window]",
                    old_len, new_len
                ),
            ));
        }

        let conv = self.conversation.clone();
        let model = self.model.clone();
        let auto_approve = self.auto_approve_turn;
        let approval_profile = self.approval_profile.clone();
        let thinking_budget = self.thinking_budget;
        let audit_session_id = self.audit_session_id.clone();

        // Build tool descriptions and runtime context for the system prompt.
        let tool_descs = get_tool_descriptions(&self.skill_registry);
        let approval_ctx = approval_context_for_prompt(&approval_profile);
        let runtime_ctx =
            system_prompt::gather_runtime_context(self.client.as_ref(), &self.model);
        let sys_prompt = system_prompt::build_system_prompt(
            &tool_descs,
            Some(approval_ctx),
            PromptMode::Full,
            Some(&runtime_ctx),
        );

        // Get LLM tool definitions via the daemon.
        let tool_defs = get_tool_definitions_json(&self.skill_registry);

        let socket_path = aegis_types::daemon::daemon_dir().join("daemon.sock");

        let (event_tx, event_rx) = mpsc::channel();
        let (approval_tx, approval_rx) = mpsc::channel();
        self.agent_rx = Some(event_rx);
        self.approval_tx = Some(approval_tx);

        // Reset abort flag for new request.
        self.abort_flag.store(false, Ordering::Relaxed);
        let abort_flag = self.abort_flag.clone();

        // Snapshot skill manifests + paths for the agent loop thread.
        let skill_manifests: Vec<_> = self
            .skill_registry
            .list()
            .iter()
            .map(|inst| {
                (
                    inst.manifest.name.clone(),
                    inst.manifest.clone(),
                    inst.path.clone(),
                )
            })
            .collect();

        std::thread::spawn(move || {
            // Clone tx for the panic guard -- if the closure panics, we still
            // send Error + Done so the UI thread doesn't hang on "Thinking...".
            let panic_tx = event_tx.clone();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let params = AgentLoopParams {
                socket_path,
                conversation: conv,
                model,
                sys_prompt,
                tool_defs,
                auto_approve,
                approval_profile,
                thinking_budget,
                audit_session_id,
                abort_flag,
                skill_manifests,
            };
            // Orchestrator always uses the provider-backed agentic loop.
            // Coding work is delegated to subagents via the "task" tool.
            run_agent_loop(params, event_tx, approval_rx);
            })); // end catch_unwind closure
            if result.is_err() {
                let _ = panic_tx.send(AgentLoopEvent::Error(
                    "Internal error: agent loop panicked".to_string(),
                ));
                let _ = panic_tx.send(AgentLoopEvent::Done);
            }
        });
    }

    /// Handle an approval keypress (y/n/a) when waiting for tool approval.
    fn handle_approval_key(&mut self, approved: bool, approve_all: bool) {
        if approve_all {
            self.auto_approve_turn = true;
        }

        // Update the last permission message to show resolved state.
        if let Some(msg) = self.messages.last_mut() {
            if let MessageRole::Permission {
                ref prompt,
                ref diff_preview,
                ..
            } = msg.role
            {
                msg.role = MessageRole::Permission {
                    prompt: prompt.clone(),
                    resolved: Some(approved),
                    diff_preview: diff_preview.clone(),
                };
            }
        }

        // Send decision to the background thread.
        if let Some(ref tx) = self.approval_tx {
            let _ = tx.send(approved);
        }

        self.awaiting_approval = false;
        self.pending_tool_desc = None;
    }

    /// Handle a key event.
    pub fn handle_key(&mut self, key: KeyEvent) {
        // Only handle key press events (not release/repeat).
        if key.kind != KeyEventKind::Press {
            return;
        }

        // If an overlay is active, route all input there.
        if self.overlay.is_some() {
            self.handle_overlay_key(key);
            return;
        }

        // Ctrl+C: cancel or quit
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            match self.input_mode {
                InputMode::Command => {
                    self.input_mode = InputMode::Chat;
                    self.command_buffer.clear();
                    self.command_cursor = 0;
                    self.command_completions.clear();
                    self.completion_idx = None;
                }
                InputMode::Chat if !self.input_buffer.is_empty() => {
                    self.input_buffer.clear();
                    self.input_cursor = 0;
                }
                InputMode::Scroll => {
                    self.input_mode = InputMode::Chat;
                }
                _ => {
                    // Auto-save on quit if conversation is non-empty.
                    if !self.conversation.is_empty() {
                        let _ = persistence::save_conversation(
                            &self.session_id,
                            &self.conversation,
                            &self.model,
                        );
                    }
                    hooks::fire_hook_event(hooks::ChatHookEvent::SessionEnd {
                        session_id: self.session_id.clone(),
                        message_count: self.conversation.len(),
                    });
                    self.running = false;
                }
            }
            return;
        }

        self.clear_stale_result();

        // Handle Escape globally before per-mode dispatch.
        if key.code == KeyCode::Esc {
            let is_double = self
                .last_esc_at
                .is_some_and(|t| t.elapsed().as_millis() < 400);
            self.last_esc_at = Some(std::time::Instant::now());

            if is_double && !self.snapshots.is_empty() {
                // Double Esc: open the conversation restore picker.
                self.overlay = Some(Overlay::RestorePicker {
                    snapshots: self.snapshots.clone(),
                    selected: 0,
                });
                return;
            }

            if self.awaiting_response {
                self.abort_current_request();
                return;
            }

            if !self.input_buffer.is_empty() {
                // Clear the current input, discarding any history navigation.
                self.input_buffer.clear();
                self.input_cursor = 0;
                self.history_index = None;
                self.input_draft.clear();
                return;
            }
            // Buffer is empty -- fall through so per-mode handlers can switch
            // between Chat/Scroll as before.
        }

        match self.input_mode {
            InputMode::Chat => self.handle_chat_key(key),
            InputMode::Scroll => self.handle_scroll_key(key),
            InputMode::Command => self.handle_command_key(key),
        }
    }

    /// Handle keys in Chat mode (default, input focused).
    fn handle_chat_key(&mut self, key: KeyEvent) {
        // Handle approval keys when waiting for tool approval.
        if self.awaiting_approval {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    self.handle_approval_key(true, false);
                }
                KeyCode::Char('a') | KeyCode::Char('A') => {
                    self.handle_approval_key(true, true);
                }
                KeyCode::Char('n') | KeyCode::Char('N') => {
                    self.handle_approval_key(false, false);
                }
                _ => {} // Ignore other keys during approval
            }
            return;
        }

        match key.code {
            KeyCode::Enter => {
                if self.awaiting_response {
                    return; // Don't stack requests
                }
                if !self.input_buffer.is_empty() {
                    let text = self.input_buffer.clone();

                    // Bang command: !<cmd> runs locally, not through the LLM.
                    if text.starts_with('!') && text.len() > 1 {
                        self.execute_bang_command(&text[1..]);
                        self.input_history.push(text);
                        self.history_index = None;
                        self.input_buffer.clear();
                        self.input_cursor = 0;
                        return;
                    }

                    // Add to conversation and display
                    self.conversation.push(LlmMessage::user(text.clone()));
                    self.messages
                        .push(ChatMessage::new(MessageRole::User, text.clone()));
                    self.scroll_offset = 0;

                    // Send to LLM
                    self.awaiting_response = true;
                    self.send_llm_request();

                    // Update input state
                    self.input_history.push(text);
                    self.history_index = None;
                    self.input_buffer.clear();
                    self.input_cursor = 0;
                }
            }
            KeyCode::Up => {
                // Browse input history backward (shell-style).
                if !self.input_history.is_empty() {
                    if self.history_index.is_none() {
                        // Save current buffer as draft before entering history.
                        self.input_draft = self.input_buffer.clone();
                    }
                    let idx = match self.history_index {
                        Some(0) => 0,
                        Some(i) => i - 1,
                        None => self.input_history.len() - 1,
                    };
                    self.history_index = Some(idx);
                    self.input_buffer = self.input_history[idx].clone();
                    self.input_cursor = self.input_buffer.len();
                }
            }
            KeyCode::Down => {
                // Browse input history forward (shell-style).
                match self.history_index {
                    Some(i) if i + 1 < self.input_history.len() => {
                        self.history_index = Some(i + 1);
                        self.input_buffer = self.input_history[i + 1].clone();
                        self.input_cursor = self.input_buffer.len();
                    }
                    Some(_) => {
                        // Past the end -- restore draft.
                        self.history_index = None;
                        self.input_buffer = self.input_draft.clone();
                        self.input_cursor = self.input_buffer.len();
                        self.input_draft.clear();
                    }
                    None => {}
                }
            }
            KeyCode::Char('/') if self.input_buffer.is_empty() => {
                self.enter_command_mode();
            }
            KeyCode::Esc if self.awaiting_response => {
                self.abort_current_request();
            }
            KeyCode::Esc if self.input_buffer.is_empty() => {
                self.input_mode = InputMode::Scroll;
            }
            // Text editing
            KeyCode::Char(c) if key.modifiers.contains(KeyModifiers::CONTROL) => match c {
                'a' => self.input_cursor = 0,
                'e' => self.input_cursor = self.input_buffer.len(),
                'u' => {
                    self.input_buffer.drain(..self.input_cursor);
                    self.input_cursor = 0;
                }
                'w' => {
                    if self.input_cursor > 0 {
                        let new_pos =
                            delete_word_backward_pos(&self.input_buffer, self.input_cursor);
                        self.input_buffer.drain(new_pos..self.input_cursor);
                        self.input_cursor = new_pos;
                    }
                }
                _ => {}
            },
            KeyCode::Char(c) => {
                self.input_buffer.insert(self.input_cursor, c);
                self.input_cursor += c.len_utf8();
            }
            KeyCode::Backspace => {
                if self.input_cursor > 0 {
                    let prev = self.input_buffer[..self.input_cursor]
                        .char_indices()
                        .next_back()
                        .map(|(i, _)| i)
                        .unwrap_or(0);
                    self.input_buffer.remove(prev);
                    self.input_cursor = prev;
                }
            }
            KeyCode::Left => {
                if self.input_cursor > 0 {
                    self.input_cursor = self.input_buffer[..self.input_cursor]
                        .char_indices()
                        .next_back()
                        .map(|(i, _)| i)
                        .unwrap_or(0);
                }
            }
            KeyCode::Right => {
                if self.input_cursor < self.input_buffer.len() {
                    self.input_cursor = self.input_buffer[self.input_cursor..]
                        .char_indices()
                        .nth(1)
                        .map(|(i, _)| self.input_cursor + i)
                        .unwrap_or(self.input_buffer.len());
                }
            }
            KeyCode::Delete => {
                if self.input_cursor < self.input_buffer.len() {
                    self.input_buffer.remove(self.input_cursor);
                }
            }
            KeyCode::Home => {
                self.input_cursor = 0;
            }
            KeyCode::End => {
                self.input_cursor = self.input_buffer.len();
            }
            _ => {}
        }
    }

    /// Handle keys in Scroll mode (message history navigation).
    fn handle_scroll_key(&mut self, key: KeyEvent) {
        let max_scroll = self.total_visual_lines.saturating_sub(1);
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.scroll_offset = self.scroll_offset.saturating_sub(1);
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.scroll_offset = (self.scroll_offset + 1).min(max_scroll);
            }
            KeyCode::Char('g') | KeyCode::Home => {
                self.scroll_offset = max_scroll;
            }
            KeyCode::Char('G') | KeyCode::End => {
                self.scroll_offset = 0;
            }
            KeyCode::PageUp => {
                self.scroll_offset = (self.scroll_offset + 20).min(max_scroll);
            }
            KeyCode::PageDown => {
                self.scroll_offset = self.scroll_offset.saturating_sub(20);
            }
            KeyCode::Esc => {
                self.input_mode = InputMode::Chat;
            }
            KeyCode::Char('/') => {
                self.enter_command_mode();
            }
            KeyCode::Char(c) => {
                // Any printable char goes back to Chat mode and inserts it
                self.input_mode = InputMode::Chat;
                self.input_buffer.insert(self.input_cursor, c);
                self.input_cursor += c.len_utf8();
            }
            _ => {}
        }
    }

    /// Enter command mode.
    fn enter_command_mode(&mut self) {
        self.input_mode = InputMode::Command;
        self.command_buffer.clear();
        self.command_cursor = 0;
        self.command_completions.clear();
        self.completion_idx = None;
        self.command_result = None;
        self.command_result_at = None;
        self.command_history_index = None;
    }

    /// Handle keys in Command mode (/ bar).
    fn handle_command_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.input_mode = InputMode::Chat;
                self.command_buffer.clear();
                self.command_cursor = 0;
                self.command_completions.clear();
                self.completion_idx = None;
            }
            KeyCode::Enter => {
                let buffer = self.command_buffer.clone();
                if !buffer.is_empty() {
                    self.command_history.push(buffer.clone());
                    self.execute_command(&buffer);
                }
                self.input_mode = InputMode::Chat;
                self.command_buffer.clear();
                self.command_cursor = 0;
                self.command_completions.clear();
                self.completion_idx = None;
            }
            KeyCode::Tab => {
                self.cycle_completion();
            }
            KeyCode::BackTab => {
                self.cycle_completion_back();
            }
            KeyCode::Up => {
                self.command_history_prev();
            }
            KeyCode::Down => {
                self.command_history_next();
            }
            KeyCode::Char(c) if key.modifiers.contains(KeyModifiers::CONTROL) => match c {
                'a' => self.command_cursor = 0,
                'e' => self.command_cursor = self.command_buffer.len(),
                'u' => {
                    self.command_buffer.drain(..self.command_cursor);
                    self.command_cursor = 0;
                    self.update_completions();
                }
                'w' => {
                    if self.command_cursor > 0 {
                        let new_pos =
                            delete_word_backward_pos(&self.command_buffer, self.command_cursor);
                        self.command_buffer.drain(new_pos..self.command_cursor);
                        self.command_cursor = new_pos;
                        self.update_completions();
                    }
                }
                _ => {}
            },
            KeyCode::Char(c) => {
                self.command_buffer.insert(self.command_cursor, c);
                self.command_cursor += c.len_utf8();
                self.update_completions();
            }
            KeyCode::Backspace => {
                if self.command_cursor > 0 {
                    let prev = self.command_buffer[..self.command_cursor]
                        .char_indices()
                        .next_back()
                        .map(|(i, _)| i)
                        .unwrap_or(0);
                    self.command_buffer.remove(prev);
                    self.command_cursor = prev;
                    self.update_completions();
                }
            }
            KeyCode::Left => {
                if self.command_cursor > 0 {
                    self.command_cursor = self.command_buffer[..self.command_cursor]
                        .char_indices()
                        .next_back()
                        .map(|(i, _)| i)
                        .unwrap_or(0);
                }
            }
            KeyCode::Right => {
                if self.command_cursor < self.command_buffer.len() {
                    self.command_cursor = self.command_buffer[self.command_cursor..]
                        .char_indices()
                        .nth(1)
                        .map(|(i, _)| self.command_cursor + i)
                        .unwrap_or(self.command_buffer.len());
                }
            }
            KeyCode::Delete => {
                if self.command_cursor < self.command_buffer.len() {
                    self.command_buffer.remove(self.command_cursor);
                    self.update_completions();
                }
            }
            KeyCode::Home => {
                self.command_cursor = 0;
            }
            KeyCode::End => {
                self.command_cursor = self.command_buffer.len();
            }
            _ => {}
        }
    }

    /// Update tab completions based on current buffer.
    fn update_completions(&mut self) {
        self.command_completions =
            local_completions(&self.command_buffer, &self.skill_command_names);
        self.completion_idx = None;
    }

    /// Cycle to the next completion.
    fn cycle_completion(&mut self) {
        if self.command_completions.is_empty() {
            self.update_completions();
            if self.command_completions.is_empty() {
                return;
            }
        }
        let idx = match self.completion_idx {
            Some(i) => (i + 1) % self.command_completions.len(),
            None => 0,
        };
        self.completion_idx = Some(idx);
        let completion = self.command_completions[idx].clone();
        self.command_buffer = apply_completion(&self.command_buffer, &completion);
        self.command_cursor = self.command_buffer.len();
    }

    /// Cycle to the previous completion.
    fn cycle_completion_back(&mut self) {
        if self.command_completions.is_empty() {
            self.update_completions();
            if self.command_completions.is_empty() {
                return;
            }
        }
        let idx = match self.completion_idx {
            Some(0) | None => self.command_completions.len() - 1,
            Some(i) => i - 1,
        };
        self.completion_idx = Some(idx);
        let completion = self.command_completions[idx].clone();
        self.command_buffer = apply_completion(&self.command_buffer, &completion);
        self.command_cursor = self.command_buffer.len();
    }

    /// Navigate to previous command in history.
    fn command_history_prev(&mut self) {
        if self.command_history.is_empty() {
            return;
        }
        let idx = match self.command_history_index {
            Some(0) => 0,
            Some(i) => i - 1,
            None => self.command_history.len() - 1,
        };
        self.command_history_index = Some(idx);
        self.command_buffer = self.command_history[idx].clone();
        self.command_cursor = self.command_buffer.len();
    }

    /// Navigate to next command in history.
    fn command_history_next(&mut self) {
        match self.command_history_index {
            Some(i) if i + 1 < self.command_history.len() => {
                self.command_history_index = Some(i + 1);
                self.command_buffer = self.command_history[i + 1].clone();
                self.command_cursor = self.command_buffer.len();
            }
            Some(_) => {
                self.command_history_index = None;
                self.command_buffer.clear();
                self.command_cursor = 0;
            }
            None => {}
        }
    }

    /// Rebuild display messages from the LLM conversation history.
    ///
    /// Used after loading a saved conversation to populate the chat view.
    fn rebuild_display_messages(&mut self) {
        self.messages.clear();
        for msg in &self.conversation {
            match msg.role {
                aegis_types::llm::LlmRole::User => {
                    self.messages
                        .push(ChatMessage::new(MessageRole::User, msg.content.clone()));
                }
                aegis_types::llm::LlmRole::Assistant => {
                    self.messages.push(ChatMessage::new(
                        MessageRole::Assistant,
                        msg.content.clone(),
                    ));
                }
                _ => {} // Skip tool results and system for now
            }
        }
        self.scroll_offset = 0;
    }

    /// Execute a bang command (`!<cmd>`) -- runs a shell command locally and
    /// displays the output inline as a system message.
    fn execute_bang_command(&mut self, cmd: &str) {
        let cmd = cmd.trim();
        if cmd.is_empty() {
            return;
        }

        // Show the command in chat.
        self.messages
            .push(ChatMessage::new(MessageRole::User, format!("!{cmd}")));

        // Run locally via the user's shell.
        let output = std::process::Command::new("sh").arg("-c").arg(cmd).output();

        let result = match output {
            Ok(out) => {
                let mut text = String::new();
                let stdout = String::from_utf8_lossy(&out.stdout);
                let stderr = String::from_utf8_lossy(&out.stderr);
                if !stdout.is_empty() {
                    text.push_str(&stdout);
                }
                if !stderr.is_empty() {
                    if !text.is_empty() {
                        text.push('\n');
                    }
                    text.push_str("[stderr] ");
                    text.push_str(&stderr);
                }
                if !out.status.success() {
                    if !text.is_empty() {
                        text.push('\n');
                    }
                    text.push_str(&format!("[exit {}]", out.status));
                }
                if text.is_empty() {
                    text.push_str("[no output]");
                }
                // Truncate very long output.
                const MAX_BANG_OUTPUT: usize = 40_000;
                if text.len() > MAX_BANG_OUTPUT {
                    text.truncate(MAX_BANG_OUTPUT);
                    text.push_str("\n[...truncated]");
                }
                text
            }
            Err(e) => format!("[error] {e}"),
        };

        self.messages
            .push(ChatMessage::new(MessageRole::System, result));
        self.scroll_offset = 0;
    }

    /// Handle key events when an overlay is active.
    fn handle_overlay_key(&mut self, key: KeyEvent) {
        // Take ownership temporarily so we can match and mutate.
        let Some(overlay) = self.overlay.take() else {
            return;
        };

        match overlay {
            Overlay::ModelPicker {
                items,
                mut filter,
                mut selected,
            } => match key.code {
                KeyCode::Esc => {
                    // Close without changing model.
                }
                KeyCode::Enter => {
                    let filtered = filter_model_items(&items, &filter);
                    if let Some((model_id, _label)) = filtered.get(selected) {
                        let old = self.model.clone();
                        self.model = model_id.clone();
                        self.set_result(format!("Model: {old} -> {model_id}"));
                    }
                }
                KeyCode::Up => {
                    selected = selected.saturating_sub(1);
                    self.overlay = Some(Overlay::ModelPicker {
                        items,
                        filter,
                        selected,
                    });
                }
                KeyCode::Down => {
                    let filtered_len = filter_model_items(&items, &filter).len();
                    if selected + 1 < filtered_len {
                        selected += 1;
                    }
                    self.overlay = Some(Overlay::ModelPicker {
                        items,
                        filter,
                        selected,
                    });
                }
                KeyCode::Backspace => {
                    filter.pop();
                    selected = 0;
                    self.overlay = Some(Overlay::ModelPicker {
                        items,
                        filter,
                        selected,
                    });
                }
                KeyCode::Char(c) => {
                    filter.push(c);
                    selected = 0;
                    self.overlay = Some(Overlay::ModelPicker {
                        items,
                        filter,
                        selected,
                    });
                }
                _ => {
                    self.overlay = Some(Overlay::ModelPicker {
                        items,
                        filter,
                        selected,
                    });
                }
            },
            Overlay::SessionPicker {
                items,
                mut selected,
            } => match key.code {
                KeyCode::Esc => {
                    // Close without resuming.
                }
                KeyCode::Enter => {
                    if let Some(meta) = items.get(selected) {
                        match persistence::load_conversation(&meta.id) {
                            Ok((messages, meta)) => {
                                self.conversation = messages;
                                self.model = meta.model.clone();
                                self.session_id = meta.id.clone();
                                self.audit_session_id = None;
                                self.register_audit_session();
                                self.rebuild_display_messages();
                                self.set_result(format!(
                                    "Resumed {} ({}, {} messages)",
                                    meta.id, meta.model, meta.message_count
                                ));
                            }
                            Err(e) => {
                                self.set_result(format!("Failed to resume: {e}"));
                            }
                        }
                    }
                }
                KeyCode::Up => {
                    selected = selected.saturating_sub(1);
                    self.overlay = Some(Overlay::SessionPicker { items, selected });
                }
                KeyCode::Down => {
                    if selected + 1 < items.len() {
                        selected += 1;
                    }
                    self.overlay = Some(Overlay::SessionPicker { items, selected });
                }
                KeyCode::Char('d') | KeyCode::Delete => {
                    // Delete the selected session file.
                    if let Some(meta) = items.get(selected) {
                        let path =
                            persistence::conversations_dir().join(format!("{}.jsonl", meta.id));
                        let _ = std::fs::remove_file(&path);
                        // Rebuild the list.
                        let new_items: Vec<_> = items
                            .into_iter()
                            .enumerate()
                            .filter(|(i, _)| *i != selected)
                            .map(|(_, m)| m)
                            .collect();
                        let new_selected = selected.min(new_items.len().saturating_sub(1));
                        if new_items.is_empty() {
                            self.set_result("No saved sessions.");
                        } else {
                            self.overlay = Some(Overlay::SessionPicker {
                                items: new_items,
                                selected: new_selected,
                            });
                        }
                    }
                }
                _ => {
                    self.overlay = Some(Overlay::SessionPicker { items, selected });
                }
            },
            Overlay::Login {
                providers,
                selected,
                key_input,
            } => {
                if let Some(mut input) = key_input {
                    // Key input sub-view
                    match key.code {
                        KeyCode::Esc => {
                            // Cancel key input, go back to provider list.
                            self.overlay = Some(Overlay::Login {
                                providers,
                                selected,
                                key_input: None,
                            });
                        }
                        KeyCode::Enter => {
                            let trimmed_key = input.buffer.trim().to_string();
                            if trimmed_key.is_empty() {
                                input.error = Some("Key cannot be empty".to_string());
                                self.overlay = Some(Overlay::Login {
                                    providers,
                                    selected,
                                    key_input: Some(input),
                                });
                            } else {
                                let mut store = aegis_types::credentials::CredentialStore::load_default()
                                    .unwrap_or_default();
                                store.set(input.provider_id, trimmed_key, None, None);
                                if let Err(e) = store.save_default() {
                                    input.error = Some(format!("Save failed: {e}"));
                                    self.overlay = Some(Overlay::Login {
                                        providers,
                                        selected,
                                        key_input: Some(input),
                                    });
                                } else {
                                    let name = input.display_name.to_string();
                                    self.open_login(None);
                                    self.set_result(format!("Saved credential for {name}"));
                                }
                            }
                        }
                        KeyCode::Char('m')
                            if key
                                .modifiers
                                .contains(crossterm::event::KeyModifiers::CONTROL) =>
                        {
                            input.masked = !input.masked;
                            self.overlay = Some(Overlay::Login {
                                providers,
                                selected,
                                key_input: Some(input),
                            });
                        }
                        KeyCode::Char(c) => {
                            input.buffer.insert(input.cursor, c);
                            input.cursor += c.len_utf8();
                            input.error = None;
                            self.overlay = Some(Overlay::Login {
                                providers,
                                selected,
                                key_input: Some(input),
                            });
                        }
                        KeyCode::Backspace => {
                            if input.cursor > 0 {
                                let prev = input.buffer[..input.cursor]
                                    .char_indices()
                                    .next_back()
                                    .map(|(i, _)| i)
                                    .unwrap_or(0);
                                input.buffer.drain(prev..input.cursor);
                                input.cursor = prev;
                            }
                            input.error = None;
                            self.overlay = Some(Overlay::Login {
                                providers,
                                selected,
                                key_input: Some(input),
                            });
                        }
                        KeyCode::Left => {
                            if input.cursor > 0 {
                                input.cursor = input.buffer[..input.cursor]
                                    .char_indices()
                                    .next_back()
                                    .map(|(i, _)| i)
                                    .unwrap_or(0);
                            }
                            self.overlay = Some(Overlay::Login {
                                providers,
                                selected,
                                key_input: Some(input),
                            });
                        }
                        KeyCode::Right => {
                            if input.cursor < input.buffer.len() {
                                input.cursor = input.buffer[input.cursor..]
                                    .char_indices()
                                    .nth(1)
                                    .map(|(i, _)| input.cursor + i)
                                    .unwrap_or(input.buffer.len());
                            }
                            self.overlay = Some(Overlay::Login {
                                providers,
                                selected,
                                key_input: Some(input),
                            });
                        }
                        KeyCode::Home => {
                            input.cursor = 0;
                            self.overlay = Some(Overlay::Login {
                                providers,
                                selected,
                                key_input: Some(input),
                            });
                        }
                        KeyCode::End => {
                            input.cursor = input.buffer.len();
                            self.overlay = Some(Overlay::Login {
                                providers,
                                selected,
                                key_input: Some(input),
                            });
                        }
                        _ => {
                            self.overlay = Some(Overlay::Login {
                                providers,
                                selected,
                                key_input: Some(input),
                            });
                        }
                    }
                } else {
                    // Provider list mode
                    let mut selected = selected;
                    match key.code {
                        KeyCode::Esc => {
                            // Close login overlay.
                        }
                        KeyCode::Up => {
                            selected = selected.saturating_sub(1);
                            self.overlay = Some(Overlay::Login {
                                providers,
                                selected,
                                key_input: None,
                            });
                        }
                        KeyCode::Down => {
                            if selected + 1 < providers.len() {
                                selected += 1;
                            }
                            self.overlay = Some(Overlay::Login {
                                providers,
                                selected,
                                key_input: None,
                            });
                        }
                        KeyCode::Enter => {
                            if let Some(p) = providers.get(selected) {
                                let id = p.id;
                                let display_name = p.display_name;
                                self.overlay = Some(Overlay::Login {
                                    providers,
                                    selected,
                                    key_input: Some(LoginKeyInput {
                                        provider_id: id,
                                        display_name,
                                        buffer: String::new(),
                                        cursor: 0,
                                        masked: true,
                                        error: None,
                                    }),
                                });
                            }
                        }
                        KeyCode::Char('d') => {
                            // Delete credential.
                            if let Some(p) = providers.get(selected) {
                                let mut store =
                                    aegis_types::credentials::CredentialStore::load_default()
                                        .unwrap_or_default();
                                store.remove(p.id);
                                let _ = store.save_default();
                                let name = p.display_name.to_string();
                                self.open_login(None);
                                self.set_result(format!("Removed credential for {name}"));
                            }
                        }
                        _ => {
                            self.overlay = Some(Overlay::Login {
                                providers,
                                selected,
                                key_input: None,
                            });
                        }
                    }
                }
            }
            Overlay::Settings { mut selected } => match key.code {
                KeyCode::Esc => {
                    // Close settings.
                }
                KeyCode::Up => {
                    selected = selected.saturating_sub(1);
                    self.overlay = Some(Overlay::Settings { selected });
                }
                KeyCode::Down => {
                    // 5 settings rows (0..4).
                    if selected < 4 {
                        selected += 1;
                    }
                    self.overlay = Some(Overlay::Settings { selected });
                }
                KeyCode::Enter | KeyCode::Right | KeyCode::Char(' ') => {
                    self.cycle_setting(selected, false);
                    self.overlay = Some(Overlay::Settings { selected });
                }
                KeyCode::Left => {
                    self.cycle_setting(selected, true);
                    self.overlay = Some(Overlay::Settings { selected });
                }
                _ => {
                    self.overlay = Some(Overlay::Settings { selected });
                }
            },
            Overlay::RestorePicker {
                snapshots,
                mut selected,
            } => match key.code {
                KeyCode::Esc => {
                    // Close without restoring.
                }
                KeyCode::Up => {
                    selected = selected.saturating_sub(1);
                    self.overlay = Some(Overlay::RestorePicker { snapshots, selected });
                }
                KeyCode::Down => {
                    if selected + 1 < snapshots.len() {
                        selected += 1;
                    }
                    self.overlay = Some(Overlay::RestorePicker { snapshots, selected });
                }
                KeyCode::Enter => {
                    // selected = 0 is newest (displayed at top); original vec is oldest-first.
                    let original_idx = snapshots.len().saturating_sub(1).saturating_sub(selected);
                    if let Some(snap) = snapshots.get(original_idx) {
                        self.messages = snap.messages.clone();
                        self.conversation = snap.conversation.clone();
                        self.scroll_offset = 0;
                        self.set_result("Conversation restored.".to_string());
                    }
                }
                _ => {
                    self.overlay = Some(Overlay::RestorePicker { snapshots, selected });
                }
            },
        }
    }

    /// Cycle a setting value (used by the Settings overlay).
    ///
    /// `index`: 0 = show_usage, 1 = thinking, 2 = approval.
    /// `reverse`: cycle backward instead of forward.
    fn cycle_setting(&mut self, index: usize, reverse: bool) {
        match index {
            0 => {
                // Toggle show_usage.
                self.show_usage = !self.show_usage;
            }
            1 => {
                // Cycle thinking: off -> low -> medium -> high -> off
                let levels: &[Option<u32>] = &[None, Some(1024), Some(4096), Some(16384)];
                let current = levels
                    .iter()
                    .position(|l| *l == self.thinking_budget)
                    .unwrap_or(0);
                let next = if reverse {
                    if current == 0 {
                        levels.len() - 1
                    } else {
                        current - 1
                    }
                } else {
                    (current + 1) % levels.len()
                };
                self.thinking_budget = levels[next];
            }
            2 => {
                // Cycle approval: Manual -> AutoEdits -> AutoHigh -> FullAuto
                let profiles = [
                    ApprovalProfile::Manual,
                    ApprovalProfile::AutoApprove(ActionRisk::Medium),
                    ApprovalProfile::AutoApprove(ActionRisk::High),
                    ApprovalProfile::FullAuto,
                ];
                let current = profiles
                    .iter()
                    .position(|p| *p == self.approval_profile)
                    .unwrap_or(0);
                let next = if reverse {
                    if current == 0 {
                        profiles.len() - 1
                    } else {
                        current - 1
                    }
                } else {
                    (current + 1) % profiles.len()
                };
                self.approval_profile = profiles[next].clone();
            }
            _ => {}
        }
    }

    /// Open the model picker overlay.
    fn open_model_picker(&mut self) {
        let mut items: Vec<(String, String)> = Vec::new();
        for provider in aegis_types::providers::ALL_PROVIDERS {
            for model in provider.models {
                items.push((
                    model.id.to_string(),
                    format!("{} ({})", model.display_name, provider.id),
                ));
            }
        }
        // Put the currently selected model at the top so it's visible.
        let current = self.model.clone();
        items.sort_by(|a, b| {
            let a_current = a.0 == current;
            let b_current = b.0 == current;
            b_current.cmp(&a_current)
        });
        self.overlay = Some(Overlay::ModelPicker {
            items,
            filter: String::new(),
            selected: 0,
        });
    }

    /// Open the session picker overlay.
    fn open_session_picker(&mut self) {
        match persistence::list_conversations() {
            Ok(items) if items.is_empty() => {
                self.set_result("No saved sessions.");
            }
            Ok(items) => {
                self.overlay = Some(Overlay::SessionPicker { items, selected: 0 });
            }
            Err(e) => {
                self.set_result(format!("Failed to list sessions: {e}"));
            }
        }
    }

    /// Open the settings overlay.
    fn open_settings(&mut self) {
        self.overlay = Some(Overlay::Settings { selected: 0 });
    }

    /// Open the login overlay for managing provider credentials.
    ///
    /// If `provider_arg` is given, jumps directly to the key input for that
    /// provider. Otherwise shows the provider list.
    fn open_login(&mut self, provider_arg: Option<&str>) {
        use aegis_types::credentials::CredentialStore;
        use aegis_types::providers::scan_providers;

        let store = CredentialStore::load_default().unwrap_or_default();
        let providers: Vec<LoginProviderEntry> = scan_providers()
            .into_iter()
            .map(|d| {
                let masked = store
                    .get(d.info.id)
                    .filter(|c| !c.api_key.is_empty())
                    .map(|c| CredentialStore::mask_key(&c.api_key));
                LoginProviderEntry {
                    id: d.info.id,
                    display_name: d.info.display_name,
                    status_label: d.status_label.clone(),
                    masked_key: masked,
                }
            })
            .collect();

        if let Some(arg) = provider_arg {
            let found = providers.iter().position(|p| p.id == arg);
            if let Some(idx) = found {
                let id = providers[idx].id;
                let display_name = providers[idx].display_name;
                self.overlay = Some(Overlay::Login {
                    providers,
                    selected: idx,
                    key_input: Some(LoginKeyInput {
                        provider_id: id,
                        display_name,
                        buffer: String::new(),
                        cursor: 0,
                        masked: true,
                        error: None,
                    }),
                });
            } else {
                self.set_result(format!(
                    "Unknown provider: {arg}. Use /login to see all."
                ));
            }
        } else {
            self.overlay = Some(Overlay::Login {
                providers,
                selected: 0,
                key_input: None,
            });
        }
    }

    /// Execute a command string.
    fn execute_command(&mut self, input: &str) {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return;
        }

        match trimmed {
            "quit" | "q" => {
                // Auto-save conversation if non-empty.
                if !self.conversation.is_empty() {
                    let _ = persistence::save_conversation(
                        &self.session_id,
                        &self.conversation,
                        &self.model,
                    );
                }
                hooks::fire_hook_event(hooks::ChatHookEvent::SessionEnd {
                    session_id: self.session_id.clone(),
                    message_count: self.conversation.len(),
                });
                self.running = false;
            }
            "clear" => {
                self.messages.clear();
                self.conversation.clear();
                self.scroll_offset = 0;
                self.set_result("Conversation cleared");
            }
            "save" => {
                if self.conversation.is_empty() {
                    self.set_result("Nothing to save (conversation is empty).");
                } else {
                    match persistence::save_conversation(
                        &self.session_id,
                        &self.conversation,
                        &self.model,
                    ) {
                        Ok(()) => {
                            self.set_result(format!("Saved as {}", self.session_id));
                        }
                        Err(e) => {
                            self.set_result(format!("Failed to save: {e}"));
                        }
                    }
                }
            }
            "sessions" | "list" => {
                self.open_session_picker();
            }
            "settings" => {
                self.open_settings();
            }
            "help" | "h" => {
                self.set_result(
                    "/quit  /clear  /new  /compact  /abort  /model [name]  /provider  /login [provider]  /mode [auto|chat|code]  /engine [auto|provider|native]  /usage  /think  /auto  /save  /resume <id>  /sessions  /settings  /daemon ...  !<cmd>  |  Skills: /debug /doc /explain /refactor /test /review /security /perf /panel-review /link-worktree",
                );
            }
            "usage" => {
                let total_tokens = self.total_input_tokens + self.total_output_tokens;
                self.set_result(format!(
                    "Session: {} tokens ({}in/{}out) | ${:.4}",
                    total_tokens,
                    self.total_input_tokens,
                    self.total_output_tokens,
                    self.total_cost_usd,
                ));
            }
            _ if trimmed.starts_with("model ") => {
                let input = trimmed.strip_prefix("model ").unwrap().trim();
                if input.is_empty() {
                    self.show_model_info();
                } else {
                    let (model_name, provider_id) = resolve_model_input(input);

                    // Warn (but don't block) if the provider has no visible auth.
                    let mut warning = String::new();
                    if let Some(pid) = provider_id {
                        if let Some(pinfo) = aegis_types::providers::provider_by_id(pid) {
                            let detected = aegis_types::providers::detect_provider(pinfo);
                            if !detected.available {
                                warning = format!(" (warning: {} not set)", pinfo.env_var,);
                            }
                        }
                    }

                    let old = self.model.clone();
                    self.model = model_name.clone();
                    let suffix = provider_id.map(|p| format!(" ({p})")).unwrap_or_default();
                    self.set_result(format!("Model: {old} -> {model_name}{suffix}{warning}"));
                }
            }
            "model" => {
                self.open_model_picker();
            }
            "provider" => {
                use aegis_types::credentials::CredentialStore;
                let store = CredentialStore::load_default().unwrap_or_default();
                let all: Vec<String> = aegis_types::providers::scan_providers()
                    .into_iter()
                    .filter(|d| d.available)
                    .map(|d| {
                        let masked = store
                            .get(d.info.id)
                            .filter(|c| !c.api_key.is_empty())
                            .map(|c| format!(" {}", CredentialStore::mask_key(&c.api_key)))
                            .unwrap_or_default();
                        format!("{} [{}]{masked}", d.info.id, d.status_label)
                    })
                    .collect();
                if all.is_empty() {
                    self.set_result(
                        "No providers available. Use /login to add credentials.",
                    );
                } else {
                    self.set_result(format!(
                        "Providers: {}  (use /login to manage)",
                        all.join(", ")
                    ));
                }
            }
            cmd if cmd == "login" || cmd.starts_with("login ") => {
                let provider_arg = cmd.strip_prefix("login").unwrap().trim();
                if provider_arg.is_empty() {
                    self.open_login(None);
                } else {
                    self.open_login(Some(provider_arg));
                }
            }
            "resume" => {
                self.set_result("Usage: /resume <id>  (use /sessions to list saved conversations)");
            }
            _ if trimmed.starts_with("resume ") => {
                let resume_id = trimmed.strip_prefix("resume ").unwrap().trim();
                if resume_id.is_empty() {
                    self.set_result("Usage: /resume <id>");
                } else {
                    match persistence::load_conversation(resume_id) {
                        Ok((messages, meta)) => {
                            self.conversation = messages;
                            self.model = meta.model.clone();
                            self.session_id = meta.id.clone();
                            // New audit session for the resumed conversation.
                            self.audit_session_id = None;
                            self.register_audit_session();
                            self.rebuild_display_messages();
                            self.set_result(format!(
                                "Resumed {} ({}, {} messages)",
                                meta.id, meta.model, meta.message_count
                            ));
                        }
                        Err(e) => {
                            self.set_result(format!("Failed to resume '{resume_id}': {e}"));
                        }
                    }
                }
            }
            "daemon start" => match crate::commands::daemon::start_quiet() {
                Ok(msg) => {
                    self.set_result(msg);
                    self.last_poll = Instant::now() - std::time::Duration::from_secs(10);
                }
                Err(e) => {
                    self.last_error = Some(format!("Failed to start daemon: {e}"));
                }
            },
            "daemon stop" => {
                if !self.connected {
                    self.set_result("Daemon is not running.");
                } else {
                    match crate::commands::daemon::stop_quiet() {
                        Ok(msg) => {
                            self.set_result(msg);
                            self.last_poll = Instant::now() - std::time::Duration::from_secs(10);
                        }
                        Err(e) => {
                            self.last_error = Some(format!("Failed to stop daemon: {e}"));
                        }
                    }
                }
            }
            "daemon status" => {
                if !self.connected {
                    self.set_result("Daemon is not running (offline mode).");
                } else {
                    self.set_result(format!(
                        "Daemon is running. Model: {}",
                        self.model,
                    ));
                }
            }
            "daemon restart" => {
                if !self.connected {
                    self.set_result("Daemon is not running. Use /daemon start.");
                } else {
                    match crate::commands::daemon::restart_quiet() {
                        Ok(msg) => {
                            self.set_result(msg);
                            self.last_poll = Instant::now() - std::time::Duration::from_secs(10);
                        }
                        Err(e) => {
                            self.last_error = Some(format!("Failed to restart daemon: {e}"));
                        }
                    }
                }
            }
            "daemon reload" => {
                if !self.connected {
                    self.set_result("Daemon is not running.");
                } else {
                    self.send_and_show_result(DaemonCommand::ReloadConfig);
                }
            }
            "daemon init" => match crate::commands::daemon::init_quiet() {
                Ok(msg) => self.set_result(msg),
                Err(e) => {
                    self.last_error = Some(format!("{e}"));
                }
            },
            "new" => {
                // Fire BeforeReset hook before clearing.
                hooks::fire_hook_event(hooks::ChatHookEvent::BeforeReset {
                    session_id: self.session_id.clone(),
                    message_count: self.conversation.len(),
                });
                // Auto-save old conversation if non-empty.
                if !self.conversation.is_empty() {
                    let _ = persistence::save_conversation(
                        &self.session_id,
                        &self.conversation,
                        &self.model,
                    );
                }
                self.messages.clear();
                self.conversation.clear();
                self.scroll_offset = 0;
                self.session_id = persistence::generate_conversation_id();
                // Register a fresh audit session for the new conversation.
                self.audit_session_id = None;
                self.register_audit_session();
                // Reset token counters.
                self.total_input_tokens = 0;
                self.total_output_tokens = 0;
                self.total_cost_usd = 0.0;
                // Fire SessionStart hook for the new session.
                hooks::fire_hook_event(hooks::ChatHookEvent::SessionStart {
                    session_id: self.session_id.clone(),
                });
                self.set_result("New session started");
            }
            "compact" => {
                if self.conversation.is_empty() {
                    self.set_result("Nothing to compact (conversation is empty).");
                } else {
                    let (estimated, threshold) =
                        compaction::should_compact(&self.conversation, &self.model);
                    match compaction::compact_conversation(&self.conversation, &self.model) {
                        Some(compacted) => {
                            let old_len = self.conversation.len();
                            let new_len = compacted.len();
                            self.conversation = compacted;
                            self.rebuild_display_messages();
                            self.set_result(format!(
                                "Compacted: {} -> {} messages (~{} -> ~{} tokens)",
                                old_len, new_len, estimated, threshold,
                            ));
                        }
                        None => {
                            self.set_result(format!(
                                "No compaction needed (~{} tokens, threshold ~{})",
                                estimated, threshold,
                            ));
                        }
                    }
                }
            }
            "abort" => {
                self.abort_current_request();
            }
            "think off" | "think" => {
                self.thinking_budget = None;
                self.set_result("Extended thinking disabled");
            }
            "think low" => {
                self.thinking_budget = Some(1024);
                self.set_result("Thinking budget: 1024 tokens");
            }
            "think medium" => {
                self.thinking_budget = Some(4096);
                self.set_result("Thinking budget: 4096 tokens");
            }
            "think high" => {
                self.thinking_budget = Some(16384);
                self.set_result("Thinking budget: 16384 tokens");
            }
            _ if trimmed.starts_with("think ") => {
                let arg = trimmed.strip_prefix("think ").unwrap().trim();
                match arg.parse::<u32>() {
                    Ok(budget) if budget > 0 => {
                        self.thinking_budget = Some(budget);
                        self.set_result(format!("Thinking budget: {budget} tokens"));
                    }
                    Ok(_) => {
                        self.set_result("Thinking budget must be greater than 0");
                    }
                    Err(_) => {
                        self.set_result(format!(
                            "Invalid thinking budget: '{arg}'. Use a number or: off, low, medium, high"
                        ));
                    }
                }
            }
            "auto off" | "auto manual" => {
                self.approval_profile = ApprovalProfile::Manual;
                self.set_result("Auto-approve: OFF (manual approval for non-safe tools)");
            }
            "auto edits" => {
                self.approval_profile = ApprovalProfile::AutoApprove(ActionRisk::Medium);
                self.set_result(
                    "Auto-approve: edits + bash (up to Medium risk). Destructive commands still ask.",
                );
            }
            "auto high" => {
                self.approval_profile = ApprovalProfile::AutoApprove(ActionRisk::High);
                self.set_result("Auto-approve: up to High risk. Only Critical actions ask.");
            }
            "auto full" => {
                self.approval_profile = ApprovalProfile::FullAuto;
                self.set_result("FULL AUTO: all tools auto-approved. Use with caution.");
            }
            "auto" => {
                let current = match &self.approval_profile {
                    ApprovalProfile::Manual => "manual (safe tools only)",
                    ApprovalProfile::AutoApprove(ActionRisk::Medium) => {
                        "auto-edits (up to medium risk)"
                    }
                    ApprovalProfile::AutoApprove(ActionRisk::High) => "auto-high (up to high risk)",
                    ApprovalProfile::AutoApprove(_) => "auto-custom",
                    ApprovalProfile::FullAuto => "full-auto (everything)",
                };
                self.set_result(format!(
                    "Current: {current}. Options: /auto off | /auto edits | /auto high | /auto full"
                ));
            }
            other => {
                // 1. Check hardcoded prompt-based skill commands.
                if let Some(skill_cmd) = SKILL_COMMANDS
                    .iter()
                    .find(|sc| other == sc.name || other.starts_with(&format!("{} ", sc.name)))
                {
                    let arg = other.strip_prefix(skill_cmd.name).unwrap_or("").trim();
                    if arg.is_empty() && skill_cmd.needs_arg {
                        self.set_result(skill_cmd.arg_hint);
                    } else {
                        self.run_skill_command(skill_cmd, arg);
                    }
                    return;
                }
                // 2. Check dynamic skill router for registered slash commands.
                let cmd_name = other.split_whitespace().next().unwrap_or("");
                if self.skill_router.route_name(cmd_name).is_some() {
                    self.dispatch_dynamic_skill(other);
                    return;
                }
                self.set_result(format!(
                    "Unknown command: '{other}'. Type /help for commands."
                ));
            }
        }
    }

    /// Execute a skill command by injecting its prompt into the conversation.
    ///
    /// Replaces `$ARGUMENTS` in the prompt template with the user's argument,
    /// adds it as a user message, and triggers an LLM request. The user sees
    /// a compact `/command arg` display message while the LLM sees the full
    /// expanded prompt.
    fn run_skill_command(&mut self, cmd: &SkillCommand, arg: &str) {
        let prompt = cmd.prompt.replace("$ARGUMENTS", arg);

        self.conversation.push(LlmMessage::user(prompt));

        let display = if arg.is_empty() {
            format!("/{}", cmd.name)
        } else {
            format!("/{} {}", cmd.name, arg)
        };
        self.messages
            .push(ChatMessage::new(MessageRole::User, display));
        self.scroll_offset = 0;
        self.awaiting_response = true;
        self.send_llm_request();
    }

    /// Dispatch a dynamic skill command via the SkillExecutor.
    ///
    /// Parses the command, looks up the skill in the router/registry,
    /// spawns a background thread with a tokio runtime to run the async
    /// executor, and sends the result back via a channel.
    fn dispatch_dynamic_skill(&mut self, input: &str) {
        let parts: Vec<&str> = input.splitn(2, ' ').collect();
        let cmd_name = parts[0].to_string();
        let args_raw = parts.get(1).copied().unwrap_or("").to_string();

        let skill_name = match self.skill_router.route_name(&cmd_name) {
            Some(name) => name.to_string(),
            None => {
                self.set_result(format!("No skill registered for /{cmd_name}"));
                return;
            }
        };

        let instance = match self.skill_registry.get(&skill_name) {
            Some(i) => i,
            None => {
                self.set_result(format!("Skill '{skill_name}' not in registry"));
                return;
            }
        };

        let manifest = instance.manifest.clone();
        let skill_dir = instance.path.clone();

        // Show the command in the chat.
        self.messages.push(ChatMessage::new(
            MessageRole::System,
            format!("Running /{cmd_name} ..."),
        ));

        let args: Vec<String> = args_raw.split_whitespace().map(String::from).collect();
        let parameters = serde_json::json!({
            "args": args,
            "raw": format!("/{input}"),
        });

        let context = aegis_skills::SkillContext {
            agent_name: Some("chat-tui".into()),
            session_id: Some(self.session_id.clone()),
            workspace_path: None,
            env_vars: Default::default(),
        };

        let (tx, rx) = mpsc::channel();
        self.skill_result_rx = Some(rx);

        let action = cmd_name.clone();
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = tx.send(SkillExecResult {
                        command_name: cmd_name,
                        output: Err(format!("failed to build runtime: {e}")),
                    });
                    return;
                }
            };
            let executor = aegis_skills::SkillExecutor::new();
            let result =
                rt.block_on(executor.execute(&manifest, &skill_dir, &action, parameters, context));
            let _ = tx.send(SkillExecResult {
                command_name: cmd_name,
                output: result.map_err(|e| format!("{e:#}")),
            });
        });
    }

    /// Poll for completed dynamic skill executions.
    fn poll_skills(&mut self) {
        let result = self
            .skill_result_rx
            .as_ref()
            .and_then(|rx| rx.try_recv().ok());
        if let Some(skill_result) = result {
            match skill_result.output {
                Ok(output) => {
                    let text = format_skill_output(&skill_result.command_name, &output);
                    self.messages
                        .push(ChatMessage::new(MessageRole::System, text));
                }
                Err(e) => {
                    self.messages.push(ChatMessage::new(
                        MessageRole::System,
                        format!("Skill error: {e}"),
                    ));
                }
            }
            self.skill_result_rx = None;
            self.scroll_offset = 0;
        }
    }

    /// Show current model and available providers.
    fn show_model_info(&mut self) {
        let providers: Vec<String> = aegis_types::providers::scan_providers()
            .into_iter()
            .filter(|d| d.available)
            .map(|d| format!("{} {}", d.info.id, d.status_label))
            .collect();
        if providers.is_empty() {
            self.set_result(format!(
                "Model: {}  |  No providers configured. Set an API key env var.",
                self.model,
            ));
        } else {
            self.set_result(format!(
                "Model: {}  |  Available: {}",
                self.model,
                providers.join(", "),
            ));
        }
    }

    /// Handle pasted text (bracketed paste).
    pub fn handle_paste(&mut self, text: &str) {
        // If a Login overlay with key input is active, paste there.
        if let Some(Overlay::Login {
            key_input: Some(ref mut input),
            ..
        }) = self.overlay
        {
            let cleaned = text.replace(['\n', '\r'], "");
            input.buffer.insert_str(input.cursor, &cleaned);
            input.cursor += cleaned.len();
            input.error = None;
            return;
        }

        match self.input_mode {
            InputMode::Command => {
                let cleaned = text.replace(['\n', '\r'], " ");
                self.command_buffer
                    .insert_str(self.command_cursor, &cleaned);
                self.command_cursor += cleaned.len();
                self.update_completions();
            }
            InputMode::Chat => {
                let cleaned = text.replace(['\n', '\r'], " ");
                self.input_buffer.insert_str(self.input_cursor, &cleaned);
                self.input_cursor += cleaned.len();
            }
            InputMode::Scroll => {
                // Switch to chat mode and paste
                self.input_mode = InputMode::Chat;
                let cleaned = text.replace(['\n', '\r'], " ");
                self.input_buffer.insert_str(self.input_cursor, &cleaned);
                self.input_cursor += cleaned.len();
            }
        }
    }

    /// Send a command to the daemon and show the response message.
    fn send_and_show_result(&mut self, cmd: DaemonCommand) {
        let Some(client) = &self.client else {
            self.last_error = Some("Not connected to daemon. Use /daemon start".into());
            return;
        };
        match client.send(&cmd) {
            Ok(resp) => {
                if resp.ok {
                    self.set_result(resp.message);
                } else {
                    self.last_error = Some(resp.message);
                }
                self.last_poll = Instant::now() - std::time::Duration::from_secs(10);
            }
            Err(e) => {
                self.last_error = Some(e);
            }
        }
    }

    /// Set the command result message with a timestamp for auto-clear.
    fn set_result(&mut self, msg: impl Into<String>) {
        self.command_result = Some(msg.into());
        self.command_result_at = Some(Instant::now());
        self.last_error = None;
    }
}

/// Get tool descriptions for the system prompt.
///
/// Returns builtin tool descriptions plus dynamically generated `skill_*`
/// tool definitions for each installed skill's commands. The `skill_` prefix
/// makes routing trivial in the agent loop.
fn get_tool_descriptions(skills: &aegis_skills::SkillRegistry) -> Vec<ToolDescription> {
    let mut descs = vec![
        ToolDescription {
            name: "bash".into(),
            description: "Run shell commands for builds, tests, git, and system administration. \
                          For capabilities covered by installed skills (audio, search, messaging, etc.), \
                          use the dedicated skill_* tools instead -- they provide structured output, \
                          subprocess isolation, and policy enforcement. Do not use bash to access \
                          credential files or inject input directly."
                .into(),
        },
        ToolDescription {
            name: "read_file".into(),
            description: "Read file contents from disk (max 500KB)".into(),
        },
        ToolDescription {
            name: "write_file".into(),
            description: "Create new files or fully replace file contents. For modifying existing \
                          files, prefer apply_patch."
                .into(),
        },
        ToolDescription {
            name: "edit_file".into(),
            description: "Replace the first occurrence of old_string with new_string in a file"
                .into(),
        },
        ToolDescription {
            name: "glob_search".into(),
            description: "Find files matching a glob pattern".into(),
        },
        ToolDescription {
            name: "grep_search".into(),
            description: "Search file contents for a regex pattern".into(),
        },
        ToolDescription {
            name: "apply_patch".into(),
            description: "Edit existing files using V4A patches. Preferred over write_file for \
                          modifications. See apply_patch instructions section for the required format."
                .into(),
        },
        ToolDescription {
            name: "file_search".into(),
            description: "Fuzzy search for files by name across the project. Respects .gitignore. \
                          Returns ranked matches with relevance scores."
                .into(),
        },
        ToolDescription {
            name: "task".into(),
            description: "Spawn a coding subagent (full agent instance with bash + file tools). \
                          Use for complex multi-step work, audio processing, data pipelines, etc. \
                          Returns a summary when done. Use run_in_background for concurrent tasks."
                .into(),
        },
    ];

    // Add skill_* tool definitions from the skill registry.
    for instance in skills.list() {
        if let Some(commands) = &instance.manifest.commands {
            for cmd in commands {
                let tool_name = format!("skill_{}", cmd.name);
                let desc = if cmd.description.is_empty() {
                    format!(
                        "Skill: {} ({}). Usage: {}",
                        instance.manifest.name, instance.manifest.description, cmd.usage,
                    )
                } else {
                    format!(
                        "{}. Usage: {}",
                        cmd.description, cmd.usage,
                    )
                };
                descs.push(ToolDescription {
                    name: tool_name,
                    description: desc,
                });
            }
        }
    }

    descs
}

/// Get the JSON Schema for a tool by name.
fn tool_schema_for(name: &str) -> serde_json::Value {
    match name {
        "bash" => serde_json::json!({
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The shell command to execute"
                }
            },
            "required": ["command"]
        }),
        "read_file" => serde_json::json!({
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Absolute path to the file to read"
                }
            },
            "required": ["file_path"]
        }),
        "write_file" => serde_json::json!({
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Absolute path to the file to write"
                },
                "content": {
                    "type": "string",
                    "description": "Content to write to the file"
                }
            },
            "required": ["file_path", "content"]
        }),
        "edit_file" => serde_json::json!({
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Absolute path to the file to edit"
                },
                "old_string": {
                    "type": "string",
                    "description": "The exact string to find and replace"
                },
                "new_string": {
                    "type": "string",
                    "description": "The replacement string"
                }
            },
            "required": ["file_path", "old_string", "new_string"]
        }),
        "glob_search" => serde_json::json!({
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Glob pattern to match files (e.g., \"**/*.rs\")"
                },
                "path": {
                    "type": "string",
                    "description": "Base directory to search in (defaults to current directory)"
                }
            },
            "required": ["pattern"]
        }),
        "grep_search" => serde_json::json!({
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Regular expression pattern to search for"
                },
                "path": {
                    "type": "string",
                    "description": "Directory or file to search in (defaults to current directory)"
                },
                "include": {
                    "type": "string",
                    "description": "Glob pattern to filter files (e.g., \"*.rs\")"
                }
            },
            "required": ["pattern"]
        }),
        "apply_patch" => serde_json::json!({
            "type": "object",
            "properties": {
                "patch": {
                    "type": "string",
                    "description": "V4A patch content. Must start with '*** Begin Patch' and end with '*** End Patch'.\nExample:\n*** Begin Patch\n*** Update File: src/main.rs\n@@ fn main():\n- old_line\n+ new_line\n*** End Patch"
                }
            },
            "required": ["patch"]
        }),
        "file_search" => serde_json::json!({
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Fuzzy search query for file names"
                },
                "path": {
                    "type": "string",
                    "description": "Directory to search in (defaults to current directory)"
                }
            },
            "required": ["query"]
        }),
        "task" => serde_json::json!({
            "type": "object",
            "properties": {
                "description": {
                    "type": "string",
                    "description": "Short (3-5 word) description of the task"
                },
                "prompt": {
                    "type": "string",
                    "description": "Detailed instructions for the subagent"
                },
                "run_in_background": {
                    "type": "boolean",
                    "description": "If true, run in background and return immediately. Default: false."
                },
                "agent": {
                    "type": "string",
                    "enum": ["auto", "claude", "codex", "llm"],
                    "description": "Which coding agent to use. 'auto' picks the best available CLI. Default: auto."
                }
            },
            "required": ["description", "prompt"]
        }),
        _ if name.starts_with("skill_") => serde_json::json!({
            "type": "object",
            "properties": {
                "args": {
                    "type": "string",
                    "description": "Space-separated arguments to pass to the skill command"
                }
            },
            "required": ["args"]
        }),
        _ => serde_json::json!({"type": "object", "properties": {}}),
    }
}

/// Build LLM tool definitions from a list of tool descriptions.
fn build_tool_definitions(descs: &[ToolDescription]) -> Option<serde_json::Value> {
    use aegis_types::llm::LlmToolDefinition;

    let defs: Vec<LlmToolDefinition> = descs
        .iter()
        .map(|td| LlmToolDefinition {
            name: td.name.clone(),
            description: td.description.clone(),
            input_schema: tool_schema_for(&td.name),
        })
        .collect();

    serde_json::to_value(&defs).ok()
}

/// Get tool definitions as JSON for the LLM request.
///
/// Returns the serialized tool definitions that will be passed to
/// `DaemonCommand::LlmComplete { tools }`.
fn get_tool_definitions_json(skills: &aegis_skills::SkillRegistry) -> Option<serde_json::Value> {
    build_tool_definitions(&get_tool_descriptions(skills))
}

/// Create a short summary of a tool call's input for display.
fn summarize_tool_input(name: &str, input: &serde_json::Value) -> String {
    match name {
        "bash" => input
            .get("command")
            .and_then(|v| v.as_str())
            .map(|s| {
                if s.len() > 80 {
                    format!("{}...", &s[..80])
                } else {
                    s.to_string()
                }
            })
            .unwrap_or_default(),
        "read_file" => input
            .get("file_path")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string(),
        "write_file" => {
            let path = input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let len = input
                .get("content")
                .and_then(|v| v.as_str())
                .map(|s| s.len())
                .unwrap_or(0);
            format!("{path} ({len} bytes)")
        }
        "edit_file" => input
            .get("file_path")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string(),
        "glob_search" => input
            .get("pattern")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string(),
        "grep_search" => input
            .get("pattern")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string(),
        "apply_patch" => {
            let patch = input.get("patch").and_then(|v| v.as_str()).unwrap_or("");
            // Show the first file operation from the patch.
            patch
                .lines()
                .find(|l| {
                    l.starts_with("*** Add File:")
                        || l.starts_with("*** Update File:")
                        || l.starts_with("*** Delete File:")
                })
                .unwrap_or("patch")
                .to_string()
        }
        "file_search" => input
            .get("query")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string(),
        "task" => input
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("subagent task")
            .to_string(),
        _ if name.starts_with("skill_") => {
            let cmd = name.strip_prefix("skill_").unwrap_or(name);
            let args = input
                .get("args")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            format!("/{cmd} {args}")
        }
        _ => serde_json::to_string(input)
            .unwrap_or_default()
            .chars()
            .take(100)
            .collect(),
    }
}

/// Maximum lines to show in a diff preview before truncating.
const MAX_DIFF_PREVIEW_LINES: usize = 30;

/// Generate a diff/content preview for a tool approval prompt.
///
/// Returns lines with prefix conventions: `+` addition (green), `-` removal
/// (red), `@` header (cyan), ` ` context (dim). The renderer colors them.
fn generate_diff_preview(name: &str, input: &serde_json::Value) -> Vec<String> {
    match name {
        "write_file" => generate_write_file_preview(input),
        "edit_file" => generate_edit_file_preview(input),
        "apply_patch" => generate_patch_preview(input),
        "bash" => {
            // Show full command (summarize_tool_input truncates at 80 chars)
            let cmd = input
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if cmd.len() > 80 {
                vec![format!("  {cmd}")]
            } else {
                vec![] // summary already shows the full thing
            }
        }
        _ => vec![],
    }
}

/// Preview for write_file: unified diff if file exists, full content if new.
fn generate_write_file_preview(input: &serde_json::Value) -> Vec<String> {
    let path = input
        .get("file_path")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let new_content = input
        .get("content")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if path.is_empty() || new_content.is_empty() {
        return vec![];
    }

    let new_lines: Vec<&str> = new_content.lines().collect();

    // Try to read existing file for a diff
    if let Ok(old_content) = std::fs::read_to_string(path) {
        let old_lines: Vec<&str> = old_content.lines().collect();
        generate_simple_diff(&old_lines, &new_lines)
    } else {
        // New file: show all lines as additions
        let mut preview = vec![format!("@ new file: {path}")];
        let total = new_lines.len();
        for line in new_lines.iter().take(MAX_DIFF_PREVIEW_LINES) {
            preview.push(format!("+{line}"));
        }
        if total > MAX_DIFF_PREVIEW_LINES {
            preview.push(format!("  ... ({} more lines)", total - MAX_DIFF_PREVIEW_LINES));
        }
        preview
    }
}

/// Preview for edit_file: show old_string as removals, new_string as additions.
fn generate_edit_file_preview(input: &serde_json::Value) -> Vec<String> {
    let path = input
        .get("file_path")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let old_str = input
        .get("old_string")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let new_str = input
        .get("new_string")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let mut preview = vec![format!("@ {path}")];
    for line in old_str.lines().take(MAX_DIFF_PREVIEW_LINES / 2) {
        preview.push(format!("-{line}"));
    }
    for line in new_str.lines().take(MAX_DIFF_PREVIEW_LINES / 2) {
        preview.push(format!("+{line}"));
    }
    preview
}

/// Preview for apply_patch: show the patch content directly.
fn generate_patch_preview(input: &serde_json::Value) -> Vec<String> {
    let patch = input
        .get("patch")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let lines: Vec<&str> = patch.lines().collect();
    let total = lines.len();
    let mut preview: Vec<String> = lines
        .into_iter()
        .take(MAX_DIFF_PREVIEW_LINES)
        .map(|l| {
            // Patch lines already have +/- prefixes or *** markers
            if l.starts_with('+') || l.starts_with('-') || l.starts_with(' ') {
                l.to_string()
            } else if l.starts_with("***") || l.starts_with("@@") {
                format!("@{l}")
            } else {
                format!(" {l}")
            }
        })
        .collect();
    if total > MAX_DIFF_PREVIEW_LINES {
        preview.push(format!("  ... ({} more lines)", total - MAX_DIFF_PREVIEW_LINES));
    }
    preview
}

/// Simple line-level diff between old and new content.
///
/// Uses a basic longest-common-subsequence approach to produce a readable
/// diff. Capped at `MAX_DIFF_PREVIEW_LINES` output lines.
fn generate_simple_diff(old_lines: &[&str], new_lines: &[&str]) -> Vec<String> {
    let mut preview = Vec::new();

    // Build LCS table
    let m = old_lines.len();
    let n = new_lines.len();

    // For very large files, fall back to a summary
    if m + n > 2000 {
        let mut p = vec![format!("@ {m} lines -> {n} lines")];
        // Show first few removed and added lines
        for line in old_lines.iter().take(5) {
            p.push(format!("-{line}"));
        }
        p.push("  ...".to_string());
        for line in new_lines.iter().take(5) {
            p.push(format!("+{line}"));
        }
        return p;
    }

    // Standard LCS dp
    let mut dp = vec![vec![0u32; n + 1]; m + 1];
    for i in 1..=m {
        for j in 1..=n {
            dp[i][j] = if old_lines[i - 1] == new_lines[j - 1] {
                dp[i - 1][j - 1] + 1
            } else {
                dp[i - 1][j].max(dp[i][j - 1])
            };
        }
    }

    // Backtrack to produce diff
    let mut diff_lines = Vec::new();
    let (mut i, mut j) = (m, n);
    while i > 0 || j > 0 {
        if i > 0 && j > 0 && old_lines[i - 1] == new_lines[j - 1] {
            diff_lines.push(format!(" {}", old_lines[i - 1]));
            i -= 1;
            j -= 1;
        } else if j > 0 && (i == 0 || dp[i][j - 1] >= dp[i - 1][j]) {
            diff_lines.push(format!("+{}", new_lines[j - 1]));
            j -= 1;
        } else {
            diff_lines.push(format!("-{}", old_lines[i - 1]));
            i -= 1;
        }
    }
    diff_lines.reverse();

    // Filter to only show changed lines with a bit of context
    let total = diff_lines.len();
    let mut last_shown = 0usize;
    let mut shown_count = 0usize;

    for (idx, line) in diff_lines.iter().enumerate() {
        let is_change = line.starts_with('+') || line.starts_with('-');
        let near_change = is_change
            || (idx > 0 && diff_lines.get(idx.wrapping_sub(1)).is_some_and(|l| l.starts_with('+') || l.starts_with('-')))
            || diff_lines.get(idx + 1).is_some_and(|l| l.starts_with('+') || l.starts_with('-'));

        if near_change {
            if idx > last_shown + 1 && shown_count > 0 {
                preview.push(format!("  ... ({} unchanged lines)", idx - last_shown - 1));
            }
            preview.push(line.clone());
            last_shown = idx;
            shown_count += 1;
            if shown_count >= MAX_DIFF_PREVIEW_LINES {
                let remaining = total - idx - 1;
                if remaining > 0 {
                    preview.push(format!("  ... ({remaining} more lines)"));
                }
                break;
            }
        }
    }

    if preview.is_empty() && !diff_lines.is_empty() {
        // No changes detected (identical content)
        preview.push("  (no changes)".to_string());
    }

    preview
}

/// Format a tool call's full content for display in the chat.
fn format_tool_call_content(name: &str, input: &serde_json::Value) -> String {
    match name {
        "bash" => input
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        "read_file" | "edit_file" => input
            .get("file_path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        "apply_patch" => input
            .get("patch")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        "file_search" => input
            .get("query")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        _ if name.starts_with("skill_") => {
            let cmd = name.strip_prefix("skill_").unwrap_or(name);
            let args = input
                .get("args")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            format!("/{cmd} {args}")
        }
        _ => serde_json::to_string_pretty(input).unwrap_or_default(),
    }
}

/// Parameters for `run_agent_loop`, grouped to stay under clippy's argument limit.
struct AgentLoopParams {
    socket_path: std::path::PathBuf,
    conversation: Vec<LlmMessage>,
    model: String,
    sys_prompt: String,
    tool_defs: Option<serde_json::Value>,
    auto_approve: bool,
    approval_profile: ApprovalProfile,
    thinking_budget: Option<u32>,
    /// Audit ledger session UUID for tool execution linkage.
    audit_session_id: Option<String>,
    /// Flag checked between iterations -- if true, the loop exits early.
    abort_flag: Arc<AtomicBool>,
    /// Skill registry snapshot for executing skill_* tool calls.
    skill_manifests: Vec<(String, aegis_skills::SkillManifest, std::path::PathBuf)>,
}

/// Run the agentic loop in a background thread.
///
/// Sends the conversation + tools to the LLM, and if the LLM returns tool
/// calls, executes them and loops. Safe tools are auto-approved; dangerous
/// tools require user approval via the `approval_rx` channel.
fn run_agent_loop(
    mut params: AgentLoopParams,
    event_tx: mpsc::Sender<AgentLoopEvent>,
    approval_rx: mpsc::Receiver<bool>,
) {
    let client = DaemonClient::new(params.socket_path.clone());
    let auto_approve_all = params.auto_approve;
    let mut conversation = std::mem::take(&mut params.conversation);

    // Maximum iterations to prevent infinite loops.
    const MAX_ITERATIONS: usize = 50;

    for _iteration in 0..MAX_ITERATIONS {
        // Check abort flag before each iteration.
        if params.abort_flag.load(Ordering::Relaxed) {
            let _ = event_tx.send(AgentLoopEvent::Done);
            return;
        }

        // Try streaming first, fall back to daemon if unsupported.
        let resp = match try_streaming_call(&params, &conversation, &event_tx) {
            Ok(r) => r,
            Err(_stream_err) => {
                // Streaming not supported for this model -- fall back to daemon.
                let messages = match serde_json::to_value(&conversation) {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = event_tx.send(AgentLoopEvent::Error(format!(
                            "failed to serialize conversation: {e}"
                        )));
                        let _ = event_tx.send(AgentLoopEvent::Done);
                        return;
                    }
                };

                let cmd = DaemonCommand::LlmComplete {
                    model: params.model.clone(),
                    messages,
                    temperature: None,
                    max_tokens: None,
                    system_prompt: Some(params.sys_prompt.clone()),
                    tools: params.tool_defs.clone(),
                };

                let result = send_with_timeout(&client, &cmd, LLM_TIMEOUT_SECS);
                match parse_llm_response(result) {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = event_tx.send(AgentLoopEvent::Error(e));
                        let _ = event_tx.send(AgentLoopEvent::Done);
                        return;
                    }
                }
            }
        };

        // Check if the LLM wants to call tools.
        let wants_tools =
            resp.stop_reason == Some(StopReason::ToolUse) && !resp.tool_calls.is_empty();

        if !wants_tools {
            // Final response -- send it and finish.
            let _ = event_tx.send(AgentLoopEvent::Response(resp));
            let _ = event_tx.send(AgentLoopEvent::Done);
            return;
        }

        // LLM wants to call tools. Send the response first (may contain text).
        let _ = event_tx.send(AgentLoopEvent::Response(resp.clone()));

        // Display all tool calls.
        let _ = event_tx.send(AgentLoopEvent::ToolCalls(resp.tool_calls.clone()));

        // Add assistant message (with tool_calls) to conversation so the next
        // LLM call sees the tool_use blocks that match the tool_result IDs.
        conversation.push(LlmMessage::assistant_with_tools(
            resp.content.clone(),
            resp.tool_calls.clone(),
        ));

        // Execute each tool call (checking abort between calls).
        for tc in &resp.tool_calls {
            if params.abort_flag.load(Ordering::Relaxed) {
                let _ = event_tx.send(AgentLoopEvent::Done);
                return;
            }
            // Fire BeforeToolCall hook.
            hooks::fire_hook_event(hooks::ChatHookEvent::BeforeToolCall {
                tool_name: tc.name.clone(),
                tool_input: tc.input.clone(),
            });
            let tool_result = if tc.name == "task" {
                // Subagent task: foreground or background.
                let prompt = tc
                    .input
                    .get("prompt")
                    .and_then(|v| v.as_str())
                    .unwrap_or("No task specified");
                let desc = tc
                    .input
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("subagent");
                let background = tc
                    .input
                    .get("run_in_background")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let agent_pref = tc
                    .input
                    .get("agent")
                    .and_then(|v| v.as_str())
                    .unwrap_or("auto");

                // Resolve which backend to use.
                let backend: Result<SubagentBackend, String> = match agent_pref {
                    "claude" => {
                        if crate::tui_utils::binary_exists("claude") {
                            Ok(SubagentBackend::ClaudeCode)
                        } else {
                            Err("claude CLI not found in PATH".to_string())
                        }
                    }
                    "codex" => {
                        if crate::tui_utils::binary_exists("codex") {
                            Ok(SubagentBackend::Codex)
                        } else {
                            Err("codex CLI not found in PATH".to_string())
                        }
                    }
                    "llm" => Ok(SubagentBackend::LlmFallback),
                    _ => Ok(detect_subagent_backend()), // "auto" or unrecognized
                };

                match backend {
                    Err(e) => Err(e),
                    Ok(SubagentBackend::LlmFallback) => {
                        if background {
                            run_background_task(&params, desc, prompt, &event_tx)
                        } else {
                            let _ = event_tx.send(AgentLoopEvent::StreamDelta(format!(
                                "\n  [Task: {desc} (LLM) ...]\n"
                            )));
                            run_subagent_task(&params, prompt, &event_tx)
                        }
                    }
                    Ok(backend) => {
                        let _ = event_tx.send(AgentLoopEvent::StreamDelta(format!(
                            "\n  [Task: {desc} ({backend:?}) ...]\n"
                        )));
                        let result = if background {
                            run_background_pilot_task(
                                desc, prompt, &event_tx, backend, &params.abort_flag,
                            )
                        } else {
                            run_pilot_subagent(
                                prompt, &event_tx, backend, &params.abort_flag,
                            )
                        };
                        // Fall back to LLM loop if pilot spawn fails.
                        match result {
                            Ok(output) => Ok(output),
                            Err(e) => {
                                let _ = event_tx.send(AgentLoopEvent::StreamDelta(format!(
                                    "  [Subagent spawn failed: {e}. Falling back to LLM loop.]\n"
                                )));
                                if background {
                                    run_background_task(&params, desc, prompt, &event_tx)
                                } else {
                                    run_subagent_task(&params, prompt, &event_tx)
                                }
                            }
                        }
                    }
                }
            } else if tc.name.starts_with("skill_") {
                // Route skill_* tool calls through the SkillExecutor.
                let cmd_name = tc.name.strip_prefix("skill_").unwrap_or(&tc.name);
                let args_str = tc
                    .input
                    .get("args")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let args: Vec<String> =
                    args_str.split_whitespace().map(String::from).collect();

                // Find the skill that owns this command.
                let skill_match = params.skill_manifests.iter().find(|(_, manifest, _)| {
                    manifest.commands.as_ref().is_some_and(|cmds| {
                        cmds.iter().any(|c| c.name == cmd_name)
                    })
                });

                match skill_match {
                    Some((_, manifest, skill_dir)) => {
                        let manifest = manifest.clone();
                        let skill_dir = skill_dir.clone();
                        let parameters = serde_json::json!({
                            "args": args,
                            "raw": format!("/{cmd_name} {args_str}"),
                        });
                        let context = aegis_skills::SkillContext {
                            agent_name: Some("chat-tui".into()),
                            session_id: params.audit_session_id.clone(),
                            workspace_path: None,
                            env_vars: Default::default(),
                        };
                        let action = cmd_name.to_string();
                        let executor = aegis_skills::SkillExecutor::new();
                        let rt = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build();
                        match rt {
                            Ok(rt) => {
                                match rt.block_on(executor.execute(
                                    &manifest, &skill_dir, &action, parameters, context,
                                )) {
                                    Ok(output) => {
                                        let text = output
                                            .result
                                            .as_str()
                                            .map(String::from)
                                            .unwrap_or_else(|| {
                                                serde_json::to_string(&output.result)
                                                    .unwrap_or_default()
                                            });
                                        Ok(text)
                                    }
                                    Err(e) => Err(format!("skill error: {e:#}")),
                                }
                            }
                            Err(e) => Err(format!("failed to build runtime: {e}")),
                        }
                    }
                    None => Err(format!("no skill found for command '{cmd_name}'")),
                }
            } else if should_auto_approve_tool(
                &tc.name,
                &tc.input,
                auto_approve_all,
                &params.approval_profile,
            ) {
                // Auto-approved -- execute directly.
                execute_tool_via_daemon(
                    &params.socket_path,
                    &tc.name,
                    &tc.input,
                    params.audit_session_id.as_deref(),
                    "chat-tui",
                )
            } else {
                // Need user approval.
                let _ = event_tx.send(AgentLoopEvent::ToolApprovalNeeded {
                    tool_call: tc.clone(),
                });

                // Wait for approval decision (blocks this thread).
                match approval_rx.recv() {
                    Ok(true) => execute_tool_via_daemon(
                        &params.socket_path,
                        &tc.name,
                        &tc.input,
                        params.audit_session_id.as_deref(),
                        "chat-tui",
                    ),
                    Ok(false) => {
                        // Tool denied by user.
                        Ok("Tool execution denied by user.".to_string())
                    }
                    Err(_) => {
                        // Channel closed -- UI exited.
                        let _ = event_tx.send(AgentLoopEvent::Done);
                        return;
                    }
                }
            };

            let result_text = match tool_result {
                Ok(text) => text,
                Err(e) => format!("Error executing {}: {e}", tc.name),
            };

            // Fire AfterToolCall hook.
            hooks::fire_hook_event(hooks::ChatHookEvent::AfterToolCall {
                tool_name: tc.name.clone(),
                result_preview: if result_text.len() > 500 {
                    format!("{}...", &result_text[..500])
                } else {
                    result_text.clone()
                },
            });

            // Send result event for UI display.
            let _ = event_tx.send(AgentLoopEvent::ToolResult {
                tool_call_id: tc.id.clone(),
                tool_name: tc.name.clone(),
                result: result_text.clone(),
            });

            // Add tool result to conversation for next LLM call.
            conversation.push(LlmMessage::tool_result(&tc.id, result_text));
        }

        // Loop back to send the updated conversation to the LLM.
    }

    // If we reach here, we hit the max iteration limit.
    let _ = event_tx.send(AgentLoopEvent::Error(
        "Agentic loop exceeded maximum iterations (50). Stopping.".into(),
    ));
    let _ = event_tx.send(AgentLoopEvent::Done);
}

/// Attempt a streaming LLM call. Returns `Err` if the model doesn't support
/// streaming (caller should fall back to the daemon's blocking path).
fn try_streaming_call(
    params: &AgentLoopParams,
    conversation: &[LlmMessage],
    event_tx: &mpsc::Sender<AgentLoopEvent>,
) -> Result<LlmResponse, String> {
    let stream_params = streaming::StreamingCallParams {
        model: params.model.clone(),
        messages: conversation.to_vec(),
        system_prompt: Some(params.sys_prompt.clone()),
        tools: params.tool_defs.clone(),
        temperature: None,
        max_tokens: None,
        thinking_budget: params.thinking_budget,
    };

    let result = streaming::stream_llm_call(&stream_params, event_tx)?;
    Ok(result.response)
}

/// Parse an LLM response from a daemon response.
fn parse_llm_response(result: Result<DaemonResponse, String>) -> Result<LlmResponse, String> {
    match result {
        Ok(resp) if resp.ok => {
            if let Some(data) = resp.data {
                serde_json::from_value::<LlmResponse>(data)
                    .map_err(|e| format!("failed to parse LLM response: {e}"))
            } else {
                Err("daemon returned ok but no response data".into())
            }
        }
        Ok(resp) => Err(resp.message),
        Err(e) => Err(e),
    }
}

/// Execute a tool via the daemon's ExecuteTool command.
///
/// Passes `session_id` and `principal` so the daemon can create audit entries
/// linked to this chat session and identify the caller.
fn execute_tool_via_daemon(
    socket_path: &std::path::Path,
    tool_name: &str,
    tool_input: &serde_json::Value,
    audit_session_id: Option<&str>,
    principal: &str,
) -> Result<String, String> {
    let client = DaemonClient::new(socket_path.to_path_buf());

    let cmd = DaemonCommand::ExecuteTool {
        name: tool_name.to_string(),
        input: tool_input.clone(),
        session_id: audit_session_id.map(|s| s.to_string()),
        principal: Some(principal.to_string()),
    };

    let result = send_with_timeout(&client, &cmd, 60);

    match result {
        Ok(resp) if resp.ok => {
            if let Some(data) = resp.data {
                // Try to extract the result field from ToolOutput.
                if let Some(result_val) = data.get("result") {
                    Ok(serde_json::to_string_pretty(result_val).unwrap_or_default())
                } else {
                    Ok(serde_json::to_string_pretty(&data).unwrap_or_default())
                }
            } else {
                Ok(resp.message)
            }
        }
        Ok(resp) => Err(resp.message),
        Err(e) => Err(e),
    }
}

/// Run a foreground subagent task as a nested agentic loop.
///
/// Creates a fresh conversation with the task prompt, gives it the same
/// tools as the parent (minus `task` to prevent recursion), and runs until
/// the LLM produces a final response or hits the iteration limit.
/// All tools are auto-approved within the subagent context.
fn run_subagent_task(
    params: &AgentLoopParams,
    task_prompt: &str,
    event_tx: &mpsc::Sender<AgentLoopEvent>,
) -> Result<String, String> {
    let mut conversation = vec![LlmMessage::user(task_prompt)];

    // Build subagent tools (everything except "task" -- no recursive spawning).
    // Subagents don't get skill tools -- they use bash directly for simplicity.
    let empty_registry = aegis_skills::SkillRegistry::new();
    let tool_descs: Vec<ToolDescription> = get_tool_descriptions(&empty_registry)
        .into_iter()
        .filter(|t| t.name != "task")
        .collect();
    let sys_prompt = system_prompt::build_system_prompt(
        &tool_descs,
        Some(approval_context_for_prompt(&ApprovalProfile::FullAuto)),
        PromptMode::Minimal,
        None, // subagents don't need runtime capability context
    );
    let tool_defs = build_tool_definitions(&tool_descs);

    let subagent_params = AgentLoopParams {
        socket_path: params.socket_path.clone(),
        conversation: Vec::new(),
        model: params.model.clone(),
        sys_prompt,
        tool_defs,
        auto_approve: true,
        approval_profile: ApprovalProfile::FullAuto, // Subagents auto-approve everything.
        thinking_budget: params.thinking_budget,
        audit_session_id: params.audit_session_id.clone(), // Share parent's audit session.
        abort_flag: params.abort_flag.clone(),
        skill_manifests: Vec::new(), // Subagents don't execute skills directly.
    };

    const MAX_SUBAGENT_ITERATIONS: usize = 30;

    for _iter in 0..MAX_SUBAGENT_ITERATIONS {
        // Try streaming first, fall back to daemon.
        let resp = match try_streaming_call(&subagent_params, &conversation, event_tx) {
            Ok(r) => r,
            Err(_) => {
                let messages = serde_json::to_value(&conversation)
                    .map_err(|e| format!("serialize error: {e}"))?;
                let cmd = DaemonCommand::LlmComplete {
                    model: params.model.clone(),
                    messages,
                    temperature: None,
                    max_tokens: None,
                    system_prompt: Some(subagent_params.sys_prompt.clone()),
                    tools: subagent_params.tool_defs.clone(),
                };
                let client = DaemonClient::new(params.socket_path.clone());
                parse_llm_response(send_with_timeout(&client, &cmd, LLM_TIMEOUT_SECS))?
            }
        };

        let wants_tools =
            resp.stop_reason == Some(StopReason::ToolUse) && !resp.tool_calls.is_empty();

        if !wants_tools {
            return Ok(resp.content);
        }

        // Add assistant message (with tool_calls) to subagent conversation.
        conversation.push(LlmMessage::assistant_with_tools(
            resp.content.clone(),
            resp.tool_calls.clone(),
        ));

        // Execute tools (all auto-approved in subagent context).
        for tc in &resp.tool_calls {
            let result = execute_tool_via_daemon(
                &params.socket_path,
                &tc.name,
                &tc.input,
                params.audit_session_id.as_deref(),
                "subagent",
            )
            .unwrap_or_else(|e| format!("Error: {e}"));

            // Show subagent tool activity in parent UI.
            let _ = event_tx.send(AgentLoopEvent::StreamDelta(format!(
                "  [subagent > {}: {}]\n",
                tc.name,
                summarize_tool_input(&tc.name, &tc.input)
            )));

            conversation.push(LlmMessage::tool_result(&tc.id, result));
        }
    }

    Err("Subagent exceeded maximum iterations (30)".into())
}

/// Run a background subagent task in a separate thread.
///
/// Returns immediately with a JSON response containing the task ID and
/// output file path. The subagent runs its own agentic loop in a new
/// thread and sends a `SubagentComplete` event when done.
fn run_background_task(
    params: &AgentLoopParams,
    description: &str,
    task_prompt: &str,
    event_tx: &mpsc::Sender<AgentLoopEvent>,
) -> Result<String, String> {
    let task_id = NEXT_TASK_ID.fetch_add(1, Ordering::Relaxed);
    let task_id_str = format!("task-{task_id}");

    // Output file for results.
    let output_dir = aegis_types::daemon::daemon_dir().join("tasks");
    let _ = std::fs::create_dir_all(&output_dir);
    let output_file = output_dir.join(format!("{task_id_str}.txt"));
    let output_path = output_file.display().to_string();

    // Clone what the background thread needs.
    let bg_params = AgentLoopParams {
        socket_path: params.socket_path.clone(),
        conversation: Vec::new(),
        model: params.model.clone(),
        sys_prompt: String::new(), // built inside run_subagent_task
        tool_defs: None,
        auto_approve: true,
        approval_profile: ApprovalProfile::FullAuto, // Background tasks auto-approve everything.
        thinking_budget: params.thinking_budget,
        audit_session_id: params.audit_session_id.clone(), // Share parent's audit session.
        abort_flag: params.abort_flag.clone(),
        skill_manifests: Vec::new(), // Background tasks don't execute skills directly.
    };
    let prompt = task_prompt.to_string();
    let desc = description.to_string();
    let tx = event_tx.clone();
    let tid = task_id_str.clone();
    let ofile = output_file.clone();

    std::thread::spawn(move || {
        let result = run_subagent_task(&bg_params, &prompt, &tx);
        let result_text = match &result {
            Ok(text) => text.clone(),
            Err(e) => format!("Error: {e}"),
        };
        // Write result to output file.
        let _ = std::fs::write(&ofile, &result_text);
        // Notify parent UI.
        let _ = tx.send(AgentLoopEvent::SubagentComplete {
            task_id: tid,
            description: desc,
            result: result_text,
            output_file: ofile.display().to_string(),
        });
    });

    // Return immediately to parent agentic loop.
    Ok(serde_json::json!({
        "task_id": task_id_str,
        "status": "running",
        "output_file": output_path,
        "message": format!(
            "Background task spawned. Results will be written to {output_path}. \
             Use read_file to check output when notified."
        )
    })
    .to_string())
}

/// Spawn a real coding CLI (claude/codex) under aegis-pilot supervision.
///
/// Creates a subprocess via aegis-pilot's driver system, streams its output
/// back to the chat TUI, and returns the collected output as the tool result.
/// This is the primary path for the "task" tool when a coding CLI is available.
fn run_pilot_subagent(
    task_prompt: &str,
    event_tx: &mpsc::Sender<AgentLoopEvent>,
    backend: SubagentBackend,
    abort_flag: &Arc<AtomicBool>,
) -> Result<String, String> {
    use aegis_pilot::adapters::passthrough::PassthroughAdapter;
    use aegis_pilot::driver::{ProcessKind, SpawnStrategy, TaskInjection};
    use aegis_pilot::drivers::create_driver;
    use aegis_pilot::json_stream::JsonStreamSession;
    use aegis_pilot::jsonl::{CodexJsonProtocol, JsonlSession};
    use aegis_pilot::ndjson_fmt::format_ndjson_line;
    use aegis_pilot::session::{AgentSession, ToolKind};
    use aegis_pilot::supervisor::{self, SupervisorConfig};
    use aegis_types::config::PilotConfig;
    use aegis_types::AgentToolConfig;

    // 1. Build tool config for the selected backend.
    let tool_config = match backend {
        SubagentBackend::ClaudeCode => AgentToolConfig::ClaudeCode {
            skip_permissions: true,
            one_shot: true,
            extra_args: vec![],
        },
        SubagentBackend::Codex => AgentToolConfig::Codex {
            runtime_engine: "external".into(),
            approval_mode: "full-auto".into(),
            one_shot: true,
            extra_args: vec![],
        },
        SubagentBackend::LlmFallback => {
            return Err("LlmFallback should not reach run_pilot_subagent".into());
        }
    };

    // 2. Create driver and resolve spawn strategy.
    let driver = create_driver(&tool_config, Some("chat-subagent"));
    let working_dir = std::env::current_dir()
        .map_err(|e| format!("cannot determine working directory: {e}"))?;
    let strategy = driver.spawn_strategy(&working_dir);
    let injection = driver.task_injection(task_prompt);
    let prompt_text = match &injection {
        TaskInjection::CliArg { value, .. } => value.clone(),
        TaskInjection::Stdin { text } => text.clone(),
        TaskInjection::None => String::new(),
    };

    // 3. Spawn the appropriate session type.
    let session: Box<dyn AgentSession> = match strategy {
        SpawnStrategy::Process {
            command,
            args,
            env,
            kind,
        } => match kind {
            ProcessKind::Json {
                tool: ToolKind::ClaudeCode,
                ..
            } => Box::new(
                JsonStreamSession::spawn(
                    "chat-subagent",
                    &command,
                    &args,
                    &working_dir,
                    &env,
                    &prompt_text,
                )
                .map_err(|e| format!("failed to spawn claude: {e}"))?,
            ),
            ProcessKind::Json {
                tool: ToolKind::Codex,
                global_args,
            } => {
                let protocol = CodexJsonProtocol::new(global_args);
                Box::new(
                    JsonlSession::spawn(
                        "chat-subagent",
                        protocol,
                        &command,
                        &args,
                        &working_dir,
                        &env,
                        &prompt_text,
                    )
                    .map_err(|e| format!("failed to spawn codex: {e}"))?,
                )
            }
            _ => return Err("unexpected process kind for subagent".into()),
        },
        SpawnStrategy::Pty {
            command, args, env, ..
        } => Box::new(
            aegis_pilot::pty::PtySession::spawn(&command, &args, &working_dir, &env)
                .map_err(|e| format!("failed to spawn PTY subagent: {e}"))?,
        ),
        SpawnStrategy::External => {
            return Err("external spawn strategy not supported for subagents".into());
        }
    };

    let _ = event_tx.send(AgentLoopEvent::StreamDelta(format!(
        "  [Spawned {} subagent, pid {}]\n",
        driver.name(),
        session.pid()
    )));

    // 4. Create adapter (passthrough for full-auto CLIs).
    let mut adapter: Box<dyn aegis_pilot::adapter::AgentAdapter> =
        match driver.create_adapter() {
            Some(a) => a,
            None => Box::new(PassthroughAdapter),
        };

    // 5. Create policy engine (permissive -- the orchestrator already approved the task).
    let policy_dir = aegis_types::daemon::daemon_dir().join("policies");
    let engine = aegis_policy::PolicyEngine::new(&policy_dir, None).unwrap_or_else(|_| {
        let tmp = std::env::temp_dir().join("aegis-subagent-policy");
        let _ = std::fs::create_dir_all(&tmp);
        aegis_policy::PolicyEngine::new(&tmp, None).expect("policy engine from temp dir")
    });

    // 6. Configure supervisor (non-interactive, default stall settings).
    let sup_config = SupervisorConfig {
        pilot_config: PilotConfig::default(),
        principal: "chat-subagent".to_string(),
        interactive: false,
    };

    // 7. Set up output collection: supervisor -> collector thread -> chat TUI.
    let (output_tx, output_rx) = std::sync::mpsc::sync_channel::<String>(256);
    let relay_tx = event_tx.clone();
    let is_claude = backend == SubagentBackend::ClaudeCode;
    let collector_abort = abort_flag.clone();
    let collector_handle = std::thread::spawn(move || {
        let mut lines = Vec::new();
        while let Ok(line) = output_rx.recv() {
            // Format JSON output for human display.
            let display_lines = if is_claude {
                format_ndjson_line(&line)
            } else {
                aegis_pilot::json_events::format_json_line(ToolKind::Codex, &line)
            };
            for dl in &display_lines {
                let _ = relay_tx.send(AgentLoopEvent::StreamDelta(format!("  {dl}\n")));
            }
            lines.push(line);
            if collector_abort.load(Ordering::Relaxed) {
                break;
            }
        }
        lines
    });

    // 8. Abort watchdog: terminates child if user cancels.
    let abort_watch = abort_flag.clone();
    let child_pid = session.pid() as i32;
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_millis(500));
        if abort_watch.load(Ordering::Relaxed) {
            let config = aegis_pilot::kill_tree::KillTreeConfig::default();
            let _ = aegis_pilot::kill_tree::kill_tree(child_pid, &config);
            break;
        }
    });

    // 9. Run supervisor (blocks until child exits).
    let result = supervisor::run(
        session.as_ref(),
        adapter.as_mut(),
        &engine,
        &sup_config,
        None,
        Some(&output_tx),
        None,
        None,
    );

    drop(output_tx);

    let (exit_code, _stats) = result.map_err(|e| format!("supervisor error: {e}"))?;
    let collected_lines = collector_handle
        .join()
        .map_err(|_| "collector thread panicked".to_string())?;

    let _ = event_tx.send(AgentLoopEvent::StreamDelta(format!(
        "  [Subagent exited with code {exit_code}]\n"
    )));

    // 10. Return collected output, truncated for context window safety.
    if collected_lines.is_empty() {
        Ok(format!(
            "Subagent completed with exit code {exit_code} (no output)"
        ))
    } else {
        let full = collected_lines.join("\n");
        const MAX_OUTPUT: usize = 50_000;
        if full.len() > MAX_OUTPUT {
            let truncated = &full[full.len() - MAX_OUTPUT..];
            Ok(format!("...(truncated)...\n{truncated}"))
        } else {
            Ok(full)
        }
    }
}

/// Run a pilot subagent in the background, returning immediately with a task ID.
fn run_background_pilot_task(
    description: &str,
    task_prompt: &str,
    event_tx: &mpsc::Sender<AgentLoopEvent>,
    backend: SubagentBackend,
    abort_flag: &Arc<AtomicBool>,
) -> Result<String, String> {
    let task_id = NEXT_TASK_ID.fetch_add(1, Ordering::Relaxed);
    let task_id_str = format!("task-{task_id}");

    let output_dir = aegis_types::daemon::daemon_dir().join("tasks");
    let _ = std::fs::create_dir_all(&output_dir);
    let output_file = output_dir.join(format!("{task_id_str}.txt"));
    let output_path = output_file.display().to_string();

    let prompt = task_prompt.to_string();
    let desc = description.to_string();
    let tx = event_tx.clone();
    let tid = task_id_str.clone();
    let ofile = output_file.clone();
    let abort = abort_flag.clone();

    std::thread::spawn(move || {
        let result = run_pilot_subagent(&prompt, &tx, backend, &abort);
        let result_text = match &result {
            Ok(text) => text.clone(),
            Err(e) => format!("Error: {e}"),
        };
        let _ = std::fs::write(&ofile, &result_text);
        let _ = tx.send(AgentLoopEvent::SubagentComplete {
            task_id: tid,
            description: desc,
            result: result_text,
            output_file: ofile.display().to_string(),
        });
    });

    Ok(serde_json::json!({
        "task_id": task_id_str,
        "status": "running",
        "backend": format!("{backend:?}"),
        "output_file": output_path,
        "message": format!(
            "Background task spawned via {backend:?}. Results will be written to {output_path}. \
             Use read_file to check output when notified."
        )
    })
    .to_string())
}

/// Send a command to the daemon with a custom read timeout.
///
/// Creates a new Unix socket connection with the specified timeout.
/// This is used for LLM completion requests which can take much longer
/// than the default 5-second timeout.
fn send_with_timeout(
    _client: &DaemonClient,
    command: &DaemonCommand,
    timeout_secs: u64,
) -> Result<aegis_control::daemon::DaemonResponse, String> {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::unix::net::UnixStream;

    let socket_path = aegis_types::daemon::daemon_dir().join("daemon.sock");

    let stream = UnixStream::connect(&socket_path).map_err(|e| {
        format!(
            "failed to connect to daemon at {}: {e}",
            socket_path.display()
        )
    })?;

    let timeout = Some(std::time::Duration::from_secs(timeout_secs));
    stream
        .set_read_timeout(timeout)
        .map_err(|e| format!("failed to set read timeout: {e}"))?;
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|e| format!("failed to set write timeout: {e}"))?;

    let mut writer = stream
        .try_clone()
        .map_err(|e| format!("failed to clone stream: {e}"))?;

    let mut json =
        serde_json::to_string(command).map_err(|e| format!("failed to serialize command: {e}"))?;
    json.push('\n');
    writer
        .write_all(json.as_bytes())
        .map_err(|e| format!("failed to send command: {e}"))?;
    writer
        .flush()
        .map_err(|e| format!("failed to flush: {e}"))?;

    // Cap at 10 MB
    let mut reader = BufReader::new(stream.take(10 * 1024 * 1024));
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("failed to read response: {e}"))?;

    serde_json::from_str(&line).map_err(|e| format!("failed to parse response: {e}"))
}

/// Filter model items by a search string (case-insensitive substring match).
fn filter_model_items<'a>(
    items: &'a [(String, String)],
    filter: &str,
) -> Vec<&'a (String, String)> {
    if filter.is_empty() {
        return items.iter().collect();
    }
    let lower = filter.to_lowercase();
    items
        .iter()
        .filter(|(id, label)| {
            id.to_lowercase().contains(&lower) || label.to_lowercase().contains(&lower)
        })
        .collect()
}

/// Get completions for the command buffer.
/// Format a `SkillOutput` for display in the chat area.
fn format_skill_output(command: &str, output: &aegis_skills::SkillOutput) -> String {
    let mut text = String::new();
    // Show the result.
    let result_str = match &output.result {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => "(no output)".to_string(),
        other => serde_json::to_string_pretty(other).unwrap_or_else(|_| other.to_string()),
    };
    text.push_str(&format!("[/{command}] {result_str}"));

    // Append any messages.
    for msg in &output.messages {
        text.push('\n');
        text.push_str(msg);
    }

    // Note artifacts.
    if !output.artifacts.is_empty() {
        text.push_str(&format!(
            "\n({} artifact(s) produced)",
            output.artifacts.len()
        ));
    }

    text
}

fn local_completions(input: &str, extra_commands: &[String]) -> Vec<String> {
    let static_iter = COMMANDS
        .iter()
        .filter(|c| c.starts_with(input))
        .map(|c| c.to_string());
    let dynamic_iter = extra_commands
        .iter()
        .filter(|c| c.starts_with(input))
        .cloned();
    static_iter.chain(dynamic_iter).collect()
}

/// Apply a completion to the command buffer.
///
/// Replaces the entire buffer with the completion text.
fn apply_completion(_buffer: &str, completion: &str) -> String {
    completion.to_string()
}

/// Resolve user input to a valid model + provider pair.
///
/// Handles: provider names ("openai" -> default model), known model names,
/// prefix-matched models (e.g., "gpt-custom" -> openai), and unknown
/// strings (passed through).
fn resolve_model_input(input: &str) -> (String, Option<&'static str>) {
    let input = input.trim();

    // Case 1: provider name -> default model
    if let Some(provider) = aegis_types::providers::provider_by_id(input) {
        if !provider.default_model.is_empty() {
            return (provider.default_model.to_string(), Some(provider.id));
        }
    }

    // Case 2: exact model in a provider's catalog
    for provider in aegis_types::providers::ALL_PROVIDERS {
        for model in provider.models {
            if model.id == input {
                return (input.to_string(), Some(provider.id));
            }
        }
    }

    // Case 3: prefix match for custom/unlisted models
    let lower = input.to_lowercase();
    let provider_id = if lower.starts_with("claude-") {
        Some("anthropic")
    } else if lower == "gpt-5.3-codex" || lower.starts_with("gpt-5.3-codex-") {
        Some("openai-codex")
    } else if lower.starts_with("gpt-")
        || lower.starts_with("o1-")
        || lower.starts_with("o3-")
        || lower.starts_with("o4-")
    {
        Some("openai")
    } else if lower.starts_with("gemini-") {
        Some("google")
    } else {
        None
    };

    (input.to_string(), provider_id)
}

/// Detect the default model from daemon config or available providers.
fn detect_model() -> String {
    // 1. Check daemon.toml for default_model.
    let config_path = aegis_types::daemon::daemon_config_path();
    if let Ok(config_str) = std::fs::read_to_string(config_path) {
        if let Ok(config) = aegis_types::daemon::DaemonConfig::from_toml(&config_str) {
            if let Some(model) = config.default_model {
                return model;
            }
        }
    }

    // 2. Check credential store for the user's stored model selection.
    let store = aegis_types::credentials::CredentialStore::load_default().unwrap_or_default();
    for detected in aegis_types::providers::scan_providers() {
        if detected.available {
            if let Some(cred) = store.get(detected.info.id) {
                if let Some(ref model) = cred.model {
                    return model.clone();
                }
            }
        }
    }

    // 3. Scan providers and pick the first available with a default model.
    for detected in aegis_types::providers::scan_providers() {
        if detected.available && !detected.info.default_model.is_empty() {
            return detected.info.default_model.to_string();
        }
    }

    // 4. Fallback.
    "claude-sonnet-4-6".to_string()
}

/// Run the chat TUI, connecting to the daemon at the default socket path.
pub fn run_chat_tui(auto_mode: Option<&str>) -> Result<()> {
    let client = DaemonClient::default_path();
    run_chat_tui_with_options(client, auto_mode)
}

/// Run the chat TUI with a specific client and optional auto-approval mode.
pub fn run_chat_tui_with_options(client: DaemonClient, auto_mode: Option<&str>) -> Result<()> {
    let model = detect_model();

    // Install panic hook to restore terminal on panic
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(
            std::io::stderr(),
            crossterm::terminal::LeaveAlternateScreen,
            crossterm::event::DisableBracketedPaste,
            crossterm::cursor::Show,
        );
        original_hook(info);
    }));

    // Set up terminal
    crossterm::terminal::enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    crossterm::execute!(
        stdout,
        crossterm::terminal::Clear(crossterm::terminal::ClearType::All),
        crossterm::terminal::Clear(crossterm::terminal::ClearType::Purge),
        crossterm::cursor::MoveTo(0, 0),
        crossterm::terminal::EnterAlternateScreen,
        crossterm::event::EnableBracketedPaste,
    )?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = ratatui::Terminal::new(backend)?;

    // Seed workspace with template files; detect first run.
    let is_first_run = seed_workspace();

    let events = EventHandler::new(TICK_RATE_MS);
    let mut app = ChatApp::new(Some(client), model);
    app.bootstrap_pending = is_first_run;
    if aegis_types::providers::scan_providers()
        .into_iter()
        .all(|p| !p.available)
    {
        app.messages.push(ChatMessage::new(
            MessageRole::System,
            "No LLM provider is configured yet. Use /provider to see detected options, then run `aegis auth add <provider> --method oauth` or set that provider API key env var. Local backends such as Ollama are auto-detected when running.".to_string(),
        ));
    }

    // Apply --auto CLI flag if provided.
    if let Some(mode) = auto_mode {
        app.approval_profile = parse_approval_mode(mode);
    }

    // Fire SessionStart hook.
    hooks::fire_hook_event(hooks::ChatHookEvent::SessionStart {
        session_id: app.session_id.clone(),
    });

    let result = run_event_loop(&mut terminal, &events, &mut app);

    // Restore terminal
    crossterm::terminal::disable_raw_mode()?;
    crossterm::execute!(
        terminal.backend_mut(),
        crossterm::terminal::LeaveAlternateScreen,
        crossterm::event::DisableBracketedPaste,
    )?;
    terminal.show_cursor()?;

    result
}

/// Internal event loop.
fn run_event_loop(
    terminal: &mut ratatui::Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>,
    events: &EventHandler,
    app: &mut ChatApp,
) -> Result<()> {
    while app.running {
        terminal.draw(|f| ui::draw(f, app))?;

        match events.next()? {
            AppEvent::Key(key) => app.handle_key(key),
            AppEvent::Paste(text) => app.handle_paste(&text),
            AppEvent::Mouse(_) => {}
            AppEvent::Tick => {}
        }

        app.poll_daemon();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::empty(),
        }
    }

    fn ctrl(c: char) -> KeyEvent {
        KeyEvent {
            code: KeyCode::Char(c),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::empty(),
        }
    }

    fn make_app() -> ChatApp {
        ChatApp::new(None, "claude-sonnet-4-20250514".into())
    }

    #[test]
    fn chat_app_defaults() {
        let app = make_app();
        assert!(app.running);
        assert_eq!(app.input_mode, InputMode::Chat);
        assert!(app.messages.is_empty());
        assert_eq!(app.scroll_offset, 0);
        assert!(app.input_buffer.is_empty());
        assert_eq!(app.input_cursor, 0);
        assert!(!app.connected);
        assert_eq!(app.model, "claude-sonnet-4-20250514");
        assert!(app.conversation.is_empty());
        assert!(!app.awaiting_response);
    }

    #[test]
    fn input_mode_transitions_escape_to_scroll() {
        let mut app = make_app();
        assert_eq!(app.input_mode, InputMode::Chat);
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.input_mode, InputMode::Scroll);
    }

    #[test]
    fn input_mode_escape_does_not_switch_when_buffer_has_text() {
        let mut app = make_app();
        app.handle_key(press(KeyCode::Char('a')));
        app.handle_key(press(KeyCode::Esc));
        // Should stay in Chat mode because buffer is not empty
        assert_eq!(app.input_mode, InputMode::Chat);
    }

    #[test]
    fn input_mode_slash_enters_command() {
        let mut app = make_app();
        app.handle_key(press(KeyCode::Char('/')));
        assert_eq!(app.input_mode, InputMode::Command);
    }

    #[test]
    fn input_mode_slash_inserts_when_buffer_not_empty() {
        let mut app = make_app();
        app.handle_key(press(KeyCode::Char('a')));
        app.handle_key(press(KeyCode::Char('/')));
        assert_eq!(app.input_mode, InputMode::Chat);
        assert_eq!(app.input_buffer, "a/");
    }

    #[test]
    fn command_mode_escape_returns_to_chat() {
        let mut app = make_app();
        app.handle_key(press(KeyCode::Char('/')));
        assert_eq!(app.input_mode, InputMode::Command);
        app.handle_key(press(KeyCode::Esc));
        assert_eq!(app.input_mode, InputMode::Chat);
        assert!(app.command_buffer.is_empty());
    }

    #[test]
    fn scroll_mode_escape_returns_to_chat() {
        let mut app = make_app();
        app.handle_key(press(KeyCode::Esc)); // -> Scroll
        assert_eq!(app.input_mode, InputMode::Scroll);
        app.handle_key(press(KeyCode::Esc)); // -> Chat
        assert_eq!(app.input_mode, InputMode::Chat);
    }

    #[test]
    fn scroll_mode_printable_char_returns_to_chat() {
        let mut app = make_app();
        app.handle_key(press(KeyCode::Esc)); // -> Scroll
        assert_eq!(app.input_mode, InputMode::Scroll);
        app.handle_key(press(KeyCode::Char('h')));
        assert_eq!(app.input_mode, InputMode::Chat);
        assert_eq!(app.input_buffer, "h");
    }

    #[test]
    fn scroll_mode_slash_enters_command() {
        let mut app = make_app();
        app.handle_key(press(KeyCode::Esc)); // -> Scroll
        app.handle_key(press(KeyCode::Char('/')));
        assert_eq!(app.input_mode, InputMode::Command);
    }

    #[test]
    fn ctrl_c_clears_buffer_when_not_empty() {
        let mut app = make_app();
        app.handle_key(press(KeyCode::Char('h')));
        app.handle_key(press(KeyCode::Char('i')));
        assert_eq!(app.input_buffer, "hi");
        app.handle_key(ctrl('c'));
        assert!(app.input_buffer.is_empty());
        assert!(app.running); // should not quit
    }

    #[test]
    fn ctrl_c_quits_when_buffer_empty() {
        let mut app = make_app();
        assert!(app.running);
        app.handle_key(ctrl('c'));
        assert!(!app.running);
    }

    #[test]
    fn text_input_and_cursor() {
        let mut app = make_app();
        app.handle_key(press(KeyCode::Char('h')));
        app.handle_key(press(KeyCode::Char('i')));
        assert_eq!(app.input_buffer, "hi");
        assert_eq!(app.input_cursor, 2);

        app.handle_key(press(KeyCode::Left));
        assert_eq!(app.input_cursor, 1);

        app.handle_key(press(KeyCode::Home));
        assert_eq!(app.input_cursor, 0);

        app.handle_key(press(KeyCode::End));
        assert_eq!(app.input_cursor, 2);

        app.handle_key(press(KeyCode::Backspace));
        assert_eq!(app.input_buffer, "h");
    }

    #[test]
    fn command_text_input() {
        let mut app = make_app();
        app.handle_key(press(KeyCode::Char('/')));
        app.handle_key(press(KeyCode::Char('h')));
        app.handle_key(press(KeyCode::Char('e')));
        app.handle_key(press(KeyCode::Char('l')));
        app.handle_key(press(KeyCode::Char('p')));
        assert_eq!(app.command_buffer, "help");
    }

    #[test]
    fn command_enter_executes_and_returns_to_chat() {
        let mut app = make_app();
        app.handle_key(press(KeyCode::Char('/')));
        app.handle_key(press(KeyCode::Char('q')));
        app.handle_key(press(KeyCode::Char('u')));
        app.handle_key(press(KeyCode::Char('i')));
        app.handle_key(press(KeyCode::Char('t')));
        app.handle_key(press(KeyCode::Enter));
        assert_eq!(app.input_mode, InputMode::Chat);
        assert!(!app.running);
    }

    #[test]
    fn release_events_are_ignored() {
        let mut app = make_app();
        let release = KeyEvent {
            code: KeyCode::Char('q'),
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Release,
            state: crossterm::event::KeyEventState::empty(),
        };
        app.handle_key(release);
        assert!(app.running); // Should not have processed it
    }

    #[test]
    fn enter_adds_to_conversation() {
        let mut app = make_app();
        // Type "hello"
        for c in "hello".chars() {
            app.handle_key(press(KeyCode::Char(c)));
        }
        assert_eq!(app.input_buffer, "hello");

        // Press enter -- no daemon client so LLM request will fail in thread,
        // but conversation and messages should be updated immediately.
        app.handle_key(press(KeyCode::Enter));

        assert!(app.input_buffer.is_empty());
        assert_eq!(app.conversation.len(), 1);
        assert_eq!(app.conversation[0].content, "hello");
        assert_eq!(app.messages.len(), 1);
        assert!(matches!(app.messages[0].role, MessageRole::User));
        assert_eq!(app.messages[0].content, "hello");
        assert!(app.awaiting_response);
    }

    #[test]
    fn enter_ignored_when_awaiting_response() {
        let mut app = make_app();
        app.awaiting_response = true;
        app.input_buffer = "test".into();
        app.input_cursor = 4;
        app.handle_key(press(KeyCode::Enter));
        // Should not have been processed
        assert_eq!(app.input_buffer, "test");
        assert!(app.conversation.is_empty());
    }

    #[test]
    fn clear_command_clears_conversation() {
        let mut app = make_app();
        app.conversation.push(LlmMessage::user("hello"));
        app.messages
            .push(ChatMessage::new(MessageRole::User, "hello".to_string()));
        app.scroll_offset = 5;

        app.execute_command("clear");

        assert!(app.messages.is_empty());
        assert!(app.conversation.is_empty());
        assert_eq!(app.scroll_offset, 0);
    }

    #[test]
    fn model_command_opens_picker() {
        let mut app = make_app();
        app.execute_command("model");
        assert!(app.overlay.is_some());
        assert!(matches!(app.overlay, Some(Overlay::ModelPicker { .. })));
    }

    #[test]
    fn model_command_sets_new_model() {
        let mut app = make_app();
        app.execute_command("model gpt-4o");
        assert_eq!(app.model, "gpt-4o");
        assert!(app.command_result.as_ref().unwrap().contains("gpt-4o"));
    }

    #[test]
    fn unknown_command_shows_error() {
        let mut app = make_app();
        app.execute_command("foobar");
        assert!(
            app.command_result
                .as_ref()
                .unwrap()
                .contains("Unknown command")
        );
    }

    #[test]
    fn paste_inserts_in_chat_mode() {
        let mut app = make_app();
        app.handle_paste("hello world");
        assert_eq!(app.input_buffer, "hello world");
    }

    #[test]
    fn paste_inserts_in_command_mode() {
        let mut app = make_app();
        app.handle_key(press(KeyCode::Char('/')));
        app.handle_paste("status");
        assert_eq!(app.command_buffer, "status");
    }

    #[test]
    fn paste_in_scroll_mode_switches_to_chat() {
        let mut app = make_app();
        app.handle_key(press(KeyCode::Esc)); // -> Scroll
        app.handle_paste("hello");
        assert_eq!(app.input_mode, InputMode::Chat);
        assert_eq!(app.input_buffer, "hello");
    }

    #[test]
    fn input_history_navigation() {
        let mut app = make_app();
        app.input_history = vec!["first".into(), "second".into(), "third".into()];

        // Up goes to latest (buffer must be empty)
        app.handle_key(press(KeyCode::Up));
        assert_eq!(app.input_buffer, "third");
        assert_eq!(app.history_index, Some(2));

        // Clear buffer and go up again to get "second"
        app.input_buffer.clear();
        app.input_cursor = 0;
        app.handle_key(press(KeyCode::Up));
        assert_eq!(app.input_buffer, "second");
        assert_eq!(app.history_index, Some(1));

        // Clear buffer and down goes forward back to "third"
        app.input_buffer.clear();
        app.input_cursor = 0;
        app.handle_key(press(KeyCode::Down));
        assert_eq!(app.input_buffer, "third");
        assert_eq!(app.history_index, Some(2));
    }

    #[test]
    fn poll_llm_handles_response() {
        let mut app = make_app();
        let (tx, rx) = mpsc::channel();
        app.agent_rx = Some(rx);
        app.awaiting_response = true;

        // Simulate a response + done event
        tx.send(AgentLoopEvent::Response(LlmResponse {
            content: "Hello! How can I help?".into(),
            model: "claude-sonnet-4-20250514".into(),
            usage: aegis_types::llm::LlmUsage {
                input_tokens: 10,
                output_tokens: 8,
            },
            tool_calls: vec![],
            stop_reason: None,
        }))
        .unwrap();
        tx.send(AgentLoopEvent::Done).unwrap();

        app.poll_llm();

        assert!(!app.awaiting_response);
        assert_eq!(app.messages.len(), 1);
        assert!(matches!(app.messages[0].role, MessageRole::Assistant));
        assert_eq!(app.messages[0].content, "Hello! How can I help?");
        assert_eq!(app.conversation.len(), 1);
        assert_eq!(app.conversation[0].content, "Hello! How can I help?");
    }

    #[test]
    fn poll_llm_handles_error() {
        let mut app = make_app();
        let (tx, rx) = mpsc::channel();
        app.agent_rx = Some(rx);
        app.awaiting_response = true;

        tx.send(AgentLoopEvent::Error("API key not set".into()))
            .unwrap();

        app.poll_llm();

        assert!(!app.awaiting_response);
        assert_eq!(app.messages.len(), 1);
        assert!(matches!(app.messages[0].role, MessageRole::System));
        assert!(app.messages[0].content.contains("API key not set"));
    }

    #[test]
    fn poll_llm_handles_tool_calls() {
        let mut app = make_app();
        let (tx, rx) = mpsc::channel();
        app.agent_rx = Some(rx);
        app.awaiting_response = true;

        let tool_calls = vec![LlmToolCall {
            id: "call_1".into(),
            name: "read_file".into(),
            input: serde_json::json!({"file_path": "/tmp/test.txt"}),
        }];
        tx.send(AgentLoopEvent::ToolCalls(tool_calls)).unwrap();

        app.poll_llm();

        assert_eq!(app.messages.len(), 1);
        assert!(matches!(app.messages[0].role, MessageRole::ToolCall { .. }));
    }

    #[test]
    fn poll_llm_handles_tool_result() {
        let mut app = make_app();
        let (tx, rx) = mpsc::channel();
        app.agent_rx = Some(rx);
        app.awaiting_response = true;

        tx.send(AgentLoopEvent::ToolResult {
            tool_call_id: "call_1".into(),
            tool_name: "read_file".into(),
            result: "file contents here".into(),
        })
        .unwrap();

        app.poll_llm();

        assert_eq!(app.messages.len(), 1);
        assert!(matches!(app.messages[0].role, MessageRole::System));
        assert!(app.messages[0].content.contains("file contents here"));
        // Tool result should be added to conversation
        assert_eq!(app.conversation.len(), 1);
        assert_eq!(app.conversation[0].role, aegis_types::llm::LlmRole::Tool);
    }

    #[test]
    fn approval_keys_work() {
        let mut app = make_app();
        let (_, event_rx) = mpsc::channel();
        let (approval_tx, _approval_rx) = mpsc::channel();
        app.agent_rx = Some(event_rx);
        app.approval_tx = Some(approval_tx);
        app.awaiting_approval = true;
        app.pending_tool_desc = Some("bash: ls -la".into());
        app.messages.push(ChatMessage::new(
            MessageRole::Permission {
                prompt: "bash: ls -la".into(),
                resolved: None,
                diff_preview: vec![],
            },
            "Allow bash? [y]es / [n]o / [a]ll".into(),
        ));

        app.handle_key(press(KeyCode::Char('y')));

        assert!(!app.awaiting_approval);
        assert!(app.pending_tool_desc.is_none());
        // Permission message should be resolved
        if let MessageRole::Permission { resolved, .. } = &app.messages[0].role {
            assert_eq!(*resolved, Some(true));
        } else {
            panic!("expected Permission role");
        }
    }

    #[test]
    fn approval_a_sets_auto_approve() {
        let mut app = make_app();
        let (_, event_rx) = mpsc::channel();
        let (approval_tx, _approval_rx) = mpsc::channel();
        app.agent_rx = Some(event_rx);
        app.approval_tx = Some(approval_tx);
        app.awaiting_approval = true;
        app.pending_tool_desc = Some("bash: ls -la".into());
        app.messages.push(ChatMessage::new(
            MessageRole::Permission {
                prompt: "bash: ls -la".into(),
                resolved: None,
                diff_preview: vec![],
            },
            "Allow bash?".into(),
        ));

        app.handle_key(press(KeyCode::Char('a')));

        assert!(!app.awaiting_approval);
        assert!(app.auto_approve_turn);
    }

    #[test]
    fn safe_tools_identified_correctly() {
        assert!(is_safe_tool("read_file"));
        assert!(is_safe_tool("glob_search"));
        assert!(is_safe_tool("grep_search"));
        assert!(!is_safe_tool("bash"));
        assert!(!is_safe_tool("write_file"));
        assert!(!is_safe_tool("edit_file"));
    }

    #[test]
    fn summarize_tool_input_formats_correctly() {
        assert_eq!(
            summarize_tool_input("bash", &serde_json::json!({"command": "ls -la"})),
            "ls -la"
        );
        assert_eq!(
            summarize_tool_input(
                "read_file",
                &serde_json::json!({"file_path": "/tmp/test.txt"})
            ),
            "/tmp/test.txt"
        );
        assert_eq!(
            summarize_tool_input("glob_search", &serde_json::json!({"pattern": "**/*.rs"})),
            "**/*.rs"
        );
    }

    #[test]
    fn local_completions_filters() {
        let completions = local_completions("da", &[]);
        assert!(completions.contains(&"daemon start".to_string()));
        assert!(completions.contains(&"daemon stop".to_string()));
        assert!(completions.contains(&"daemon status".to_string()));
        assert!(!completions.contains(&"quit".to_string()));
    }

    #[test]
    fn local_completions_empty_input() {
        let completions = local_completions("", &[]);
        assert_eq!(completions.len(), COMMANDS.len());
    }

    #[test]
    fn y_inserts_char_normally() {
        let mut app = make_app();
        // No pending prompts -- y should just insert the character
        app.handle_key(press(KeyCode::Char('y')));
        assert_eq!(app.input_buffer, "y");
    }

    #[test]
    fn detect_model_returns_fallback() {
        // In a test environment without daemon.toml or API keys, detect_model
        // should return a sensible default. We just verify it returns a
        // non-empty string.
        let model = detect_model();
        assert!(!model.is_empty());
    }

    // -- Risk classification ------------------------------------------------

    #[test]
    fn classify_read_file_is_informational() {
        let input = serde_json::json!({"file_path": "/tmp/test.rs"});
        assert_eq!(
            classify_tool_risk("read_file", &input),
            ActionRisk::Informational
        );
    }

    #[test]
    fn classify_write_file_is_medium() {
        let input = serde_json::json!({"file_path": "/tmp/test.rs", "content": "hello"});
        assert_eq!(classify_tool_risk("write_file", &input), ActionRisk::Medium);
    }

    #[test]
    fn classify_edit_file_is_medium() {
        let input = serde_json::json!({"file_path": "/tmp/test.rs"});
        assert_eq!(classify_tool_risk("edit_file", &input), ActionRisk::Medium);
    }

    #[test]
    fn classify_bash_ls_is_low() {
        let input = serde_json::json!({"command": "ls -la /tmp"});
        assert_eq!(classify_tool_risk("bash", &input), ActionRisk::Low);
    }

    #[test]
    fn classify_bash_git_status_is_low() {
        let input = serde_json::json!({"command": "git status"});
        assert_eq!(classify_tool_risk("bash", &input), ActionRisk::Low);
    }

    #[test]
    fn classify_bash_cargo_test_is_low() {
        let input = serde_json::json!({"command": "cargo test --workspace"});
        assert_eq!(classify_tool_risk("bash", &input), ActionRisk::Low);
    }

    #[test]
    fn classify_bash_rm_rf_is_high() {
        let input = serde_json::json!({"command": "rm -rf /tmp/project"});
        assert_eq!(classify_tool_risk("bash", &input), ActionRisk::High);
    }

    #[test]
    fn classify_bash_force_push_is_high() {
        let input = serde_json::json!({"command": "git push --force origin main"});
        assert_eq!(classify_tool_risk("bash", &input), ActionRisk::High);
    }

    #[test]
    fn classify_bash_sudo_is_high() {
        let input = serde_json::json!({"command": "sudo apt install foo"});
        assert_eq!(classify_tool_risk("bash", &input), ActionRisk::High);
    }

    #[test]
    fn classify_bash_git_commit_is_medium() {
        let input = serde_json::json!({"command": "git commit -m \"fix\""});
        assert_eq!(classify_tool_risk("bash", &input), ActionRisk::Medium);
    }

    #[test]
    fn classify_bash_general_command_is_medium() {
        let input = serde_json::json!({"command": "make build"});
        assert_eq!(classify_tool_risk("bash", &input), ActionRisk::Medium);
    }

    #[test]
    fn classify_unknown_tool_is_high() {
        let input = serde_json::json!({});
        assert_eq!(
            classify_tool_risk("some_new_tool", &input),
            ActionRisk::High
        );
    }

    // -- Approval profile logic ---------------------------------------------

    #[test]
    fn manual_profile_only_approves_safe_tools() {
        let profile = ApprovalProfile::Manual;
        let bash_input = serde_json::json!({"command": "ls"});
        assert!(!should_auto_approve_tool(
            "bash",
            &bash_input,
            false,
            &profile
        ));
        assert!(should_auto_approve_tool(
            "read_file",
            &serde_json::json!({}),
            false,
            &profile
        ));
    }

    #[test]
    fn full_auto_approves_everything() {
        let profile = ApprovalProfile::FullAuto;
        let input = serde_json::json!({"command": "rm -rf /"});
        assert!(should_auto_approve_tool("bash", &input, false, &profile));
    }

    #[test]
    fn auto_edits_approves_medium_risk() {
        let profile = ApprovalProfile::AutoApprove(ActionRisk::Medium);
        let write_input = serde_json::json!({"file_path": "/tmp/x", "content": "y"});
        assert!(should_auto_approve_tool(
            "write_file",
            &write_input,
            false,
            &profile
        ));
    }

    #[test]
    fn auto_edits_blocks_high_risk() {
        let profile = ApprovalProfile::AutoApprove(ActionRisk::Medium);
        let rm_input = serde_json::json!({"command": "rm -rf /tmp"});
        assert!(!should_auto_approve_tool(
            "bash", &rm_input, false, &profile
        ));
    }

    #[test]
    fn auto_edits_approves_low_risk_bash() {
        let profile = ApprovalProfile::AutoApprove(ActionRisk::Medium);
        let ls_input = serde_json::json!({"command": "ls -la"});
        assert!(should_auto_approve_tool("bash", &ls_input, false, &profile));
    }

    #[test]
    fn auto_approve_all_overrides_profile() {
        let profile = ApprovalProfile::Manual;
        let bash_input = serde_json::json!({"command": "rm -rf /"});
        // When user pressed 'a', auto_approve_all is true -- overrides profile.
        assert!(should_auto_approve_tool(
            "bash",
            &bash_input,
            true,
            &profile
        ));
    }

    // -- Parse approval mode ------------------------------------------------

    #[test]
    fn parse_approval_mode_variants() {
        assert_eq!(parse_approval_mode("off"), ApprovalProfile::Manual);
        assert_eq!(parse_approval_mode("manual"), ApprovalProfile::Manual);
        assert_eq!(
            parse_approval_mode("edits"),
            ApprovalProfile::AutoApprove(ActionRisk::Medium)
        );
        assert_eq!(
            parse_approval_mode("high"),
            ApprovalProfile::AutoApprove(ActionRisk::High)
        );
        assert_eq!(parse_approval_mode("full"), ApprovalProfile::FullAuto);
        assert_eq!(parse_approval_mode("full-auto"), ApprovalProfile::FullAuto);
    }

    #[test]
    fn parse_approval_mode_unknown_defaults_to_manual() {
        assert_eq!(parse_approval_mode("bogus"), ApprovalProfile::Manual);
    }

    // -- Approval profile label ---------------------------------------------

    #[test]
    fn approval_profile_labels() {
        assert_eq!(approval_profile_label(&ApprovalProfile::Manual), "manual");
        assert_eq!(
            approval_profile_label(&ApprovalProfile::AutoApprove(ActionRisk::Medium)),
            "auto-edits"
        );
        assert_eq!(
            approval_profile_label(&ApprovalProfile::AutoApprove(ActionRisk::High)),
            "auto-high"
        );
        assert_eq!(
            approval_profile_label(&ApprovalProfile::FullAuto),
            "full-auto"
        );
    }

    // -- /auto commands -----------------------------------------------------

    #[test]
    fn auto_command_sets_profile() {
        let mut app = make_app();
        assert_eq!(app.approval_profile, ApprovalProfile::Manual);

        app.execute_command("auto edits");
        assert_eq!(
            app.approval_profile,
            ApprovalProfile::AutoApprove(ActionRisk::Medium)
        );

        app.execute_command("auto high");
        assert_eq!(
            app.approval_profile,
            ApprovalProfile::AutoApprove(ActionRisk::High)
        );

        app.execute_command("auto full");
        assert_eq!(app.approval_profile, ApprovalProfile::FullAuto);

        app.execute_command("auto off");
        assert_eq!(app.approval_profile, ApprovalProfile::Manual);
    }

    #[test]
    fn auto_command_shows_status() {
        let mut app = make_app();
        app.execute_command("auto");
        assert!(app.command_result.is_some());
        let result = app.command_result.unwrap();
        assert!(result.contains("manual"));
    }

}
