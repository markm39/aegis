//! System prompt construction for chat TUI LLM requests.
//!
//! Builds a modular system prompt with sections adapted from OpenClaw's
//! architecture and Codex's coding agent instructions. Sections are stored
//! as static markdown files and included at compile time.

use std::fmt::Write;
use std::path::Path;
use std::process::Command;

use aegis_control::daemon::{DaemonClient, DaemonCommand};
use aegis_types::daemon::DaemonConfig;

/// Maximum characters to include from any single project context file.
const MAX_FILE_CHARS: usize = 20_000;

/// Maximum total characters for the entire system prompt.
const MAX_PROMPT_CHARS: usize = 100_000;

// Static prompt sections included at compile time.
const IDENTITY: &str = include_str!("prompts/identity.md");
const TOOLING_STYLE: &str = include_str!("prompts/tooling.md");
const SAFETY: &str = include_str!("prompts/safety.md");
const CODING: &str = include_str!("prompts/coding.md");
const OUTPUT_FORMATTING: &str = include_str!("prompts/output_formatting.md");
const CAPABILITIES: &str = include_str!("prompts/capabilities.md");
const APPLY_PATCH_INSTRUCTIONS: &str =
    include_str!("../../../../vendor/codex/apply-patch/apply_patch_tool_instructions.md");

// ---------------------------------------------------------------------------
// Runtime capability context
// ---------------------------------------------------------------------------

/// Summary of an installed skill for the system prompt.
pub struct SkillSummary {
    /// Skill name (directory name).
    pub name: String,
    /// One-line description extracted from SKILL.md front matter.
    pub description: Option<String>,
}

/// Runtime context gathered before building the system prompt.
///
/// Captures what features are actually available right now so the prompt
/// only describes capabilities the agent can use. Gathered best-effort:
/// missing data results in conservative defaults (feature disabled).
pub struct RuntimeContext {
    // -- Daemon state --
    pub daemon_connected: bool,
    pub agent_count: usize,
    pub running_agent_count: usize,

    // -- Channel --
    /// Configured messaging channel type (e.g. "telegram"), if any.
    pub channel_type: Option<String>,

    // -- Cron --
    pub cron_enabled: bool,
    pub cron_job_count: usize,

    // -- Toolkit / computer use --
    pub screen_capture_enabled: bool,
    pub input_injection_enabled: bool,
    pub browser_enabled: bool,

    // -- Audio / voice --
    pub tts_available: bool,
    pub stt_available: bool,
    pub mic_capture_available: bool,

    // -- Skills --
    pub installed_skills: Vec<SkillSummary>,

    // -- Runtime info --
    pub hostname: String,
    pub model: String,
    pub shell: String,
}

/// Gather runtime context from daemon state and local configuration.
///
/// Best-effort: if the daemon is unreachable or config is missing, fields
/// default to "unavailable" state. This is called once per LLM request.
pub fn gather_runtime_context(client: Option<&DaemonClient>, model: &str) -> RuntimeContext {
    let mut ctx = RuntimeContext {
        daemon_connected: false,
        agent_count: 0,
        running_agent_count: 0,
        channel_type: None,
        cron_enabled: false,
        cron_job_count: 0,
        screen_capture_enabled: false,
        input_injection_enabled: false,
        browser_enabled: false,
        tts_available: false,
        stt_available: false,
        mic_capture_available: false,
        installed_skills: Vec::new(),
        hostname: String::new(),
        model: model.to_string(),
        shell: std::env::var("SHELL").unwrap_or_default(),
    };

    // Hostname
    if let Ok(output) = Command::new("hostname").arg("-s").output() {
        if output.status.success() {
            ctx.hostname = String::from_utf8_lossy(&output.stdout).trim().to_string();
        }
    }

    // Daemon ping for live state
    if let Some(client) = client {
        if let Ok(resp) = client.send(&DaemonCommand::Ping) {
            if resp.ok {
                ctx.daemon_connected = true;
                if let Some(data) = &resp.data {
                    ctx.agent_count =
                        data.get("agent_count").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                    ctx.running_agent_count =
                        data.get("running_count").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                }
            }
        }
    }

    // Read daemon.toml for config-level capabilities (works even when daemon is down)
    if let Ok(toml_str) = std::fs::read_to_string(aegis_types::daemon::daemon_config_path()) {
        if let Ok(config) = DaemonConfig::from_toml(&toml_str) {
            // Channel
            if let Some(ref ch) = config.channel {
                ctx.channel_type = Some(ch.channel_type_name().to_string());
            }

            // Cron
            ctx.cron_enabled = config.cron.enabled;
            ctx.cron_job_count = config.cron.jobs.len();

            // Toolkit
            ctx.screen_capture_enabled = config.toolkit.capture.enabled;
            ctx.input_injection_enabled = config.toolkit.input.enabled;
            ctx.browser_enabled = config.toolkit.browser.enabled;

            // Skills discovery: scan ~/.aegis/skills/ for installed skills.
            // Each skill is a directory with a manifest.toml.
            let skills_dir = std::path::PathBuf::from(
                std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()),
            )
            .join(".aegis")
            .join("skills");
            if let Ok(entries) = std::fs::read_dir(&skills_dir) {
                let mut skills: Vec<_> = entries
                    .flatten()
                    .filter(|e| e.path().is_dir())
                    .take(50)
                    .map(|e| {
                        let name = e
                            .path()
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string();
                        let manifest = e.path().join("manifest.toml");
                        let description = read_manifest_description(&manifest)
                            .or_else(|| {
                                // Fallback: try SKILL.md
                                read_skill_description(&e.path().join("SKILL.md"))
                            });
                        SkillSummary { name, description }
                    })
                    .collect();
                skills.sort_by(|a, b| a.name.cmp(&b.name));
                ctx.installed_skills = skills;
            }
        }
    }

    // Audio: check for mic capture tools (ffmpeg used by audio-record skill)
    ctx.mic_capture_available =
        command_exists("sox") || command_exists("arecord") || command_exists("ffmpeg");
    // TTS/STT: check for whisper CLI
    ctx.stt_available = command_exists("whisper");
    // TTS: check for say (macOS) or espeak
    ctx.tts_available = command_exists("say") || command_exists("espeak");

    ctx
}

/// Check if a command exists on PATH.
fn command_exists(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Extract first line of description from a SKILL.md file.
///
/// Looks for a `description:` front matter field or falls back to the first
/// non-empty, non-heading line.
fn read_skill_description(path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    // Try front matter: "description: ..."
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "---" {
            continue;
        }
        if let Some(desc) = trimmed.strip_prefix("description:") {
            let desc = desc.trim().trim_matches('"').trim_matches('\'');
            if !desc.is_empty() {
                return Some(desc.to_string());
            }
        }
        // Stop at end of front matter
        if trimmed.is_empty() && content.starts_with("---") {
            break;
        }
    }
    // Fallback: first non-empty, non-heading line
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("---") {
            continue;
        }
        // Truncate long descriptions
        let desc = if trimmed.len() > 80 {
            format!("{}...", &trimmed[..77])
        } else {
            trimmed.to_string()
        };
        return Some(desc);
    }
    None
}

/// Extract the `description` field from a TOML manifest file.
///
/// Parses lines looking for `description = "..."`. Avoids pulling in a full
/// TOML parser since we only need one field.
fn read_manifest_description(path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("description") {
            let rest = rest.trim_start();
            if let Some(rest) = rest.strip_prefix('=') {
                let rest = rest.trim();
                let desc = rest
                    .trim_matches('"')
                    .trim_matches('\'')
                    .trim();
                if !desc.is_empty() {
                    let desc = if desc.len() > 100 {
                        format!("{}...", &desc[..97])
                    } else {
                        desc.to_string()
                    };
                    return Some(desc);
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Conditional prompt section builders
// ---------------------------------------------------------------------------

/// Self-configuration assessment pattern (always included).
fn build_self_config_section(ctx: &RuntimeContext) -> String {
    let mut s = String::from(
        "# Self-Configuration\n\n\
         You run on an always-on daemon. You can configure yourself to perform \
         tasks autonomously -- schedule recurring work, spawn coding agents, \
         and manage integrations.\n\n\
         ## Assessment Pattern\n\n\
         When asked to do something ongoing, scheduled, or complex:\n\
         1. **Understand intent** -- what outcome do they want?\n\
         2. **Assess capability** -- can you achieve this with your tools, \
         subagents, and installed skills?\n\
         3. **Identify configuration** -- what needs to change?\n\
         4. **Confirm before acting** -- show the user what you plan to configure\n\
         5. **Configure** -- edit daemon.toml if needed, then \
         `bash: aegis daemon reload`\n\
         6. **Verify** -- confirm the change took effect\n",
    );

    if ctx.daemon_connected {
        s.push_str(
            "\nThe daemon is running. You can reload config, manage agents, \
             and execute fleet commands.\n",
        );
    } else {
        s.push_str(
            "\nThe daemon is not currently running. Start it with \
             `/daemon start` or `bash: aegis daemon start`.\n",
        );
    }

    s
}

/// Computer-use / toolkit section. Returns None if no toolkit features are enabled.
fn build_toolkit_section(ctx: &RuntimeContext) -> Option<String> {
    if !ctx.screen_capture_enabled && !ctx.input_injection_enabled && !ctx.browser_enabled {
        return None;
    }
    let mut s = String::from("# Computer Use\n\nYou have direct computer-use capabilities:\n");
    if ctx.screen_capture_enabled {
        s.push_str("- **Screen capture**: Take screenshots of the desktop or specific windows\n");
    }
    if ctx.input_injection_enabled {
        s.push_str(
            "- **Input control**: Control mouse (move, click, drag) \
             and keyboard (type, press keys)\n",
        );
    }
    if ctx.browser_enabled {
        s.push_str(
            "- **Browser automation**: Control a web browser via CDP -- \
             navigate, click, type, screenshot, evaluate JavaScript, \
             manage tabs\n",
        );
    }
    s.push_str(
        "\nThese run through the toolkit orchestrator with Cedar policy \
         enforcement. Actions are classified by risk level.\n",
    );
    Some(s)
}

/// Audio and voice section. Returns None if no audio features are available.
fn build_audio_section(ctx: &RuntimeContext) -> Option<String> {
    if !ctx.mic_capture_available && !ctx.stt_available && !ctx.tts_available {
        return None;
    }
    let mut s = String::from("# Audio & Voice\n\n");
    if ctx.mic_capture_available {
        s.push_str(
            "- **Microphone capture**: Record audio from the system mic \
             (via sox/arecord in a subagent). Use this for note-taking, \
             voice memos, or ambient listening.\n",
        );
    }
    if ctx.stt_available {
        s.push_str(
            "- **Speech-to-text**: Transcribe audio files to text \
             (Whisper). Combine with mic capture for live transcription.\n",
        );
    }
    if ctx.tts_available {
        s.push_str(
            "- **Text-to-speech**: Synthesize spoken audio from text. \
             Useful for notifications or accessibility.\n",
        );
    }
    Some(s)
}

/// Cron scheduling section. Returns None if cron is not available.
fn build_cron_section(ctx: &RuntimeContext) -> Option<String> {
    if !ctx.cron_enabled && !ctx.daemon_connected {
        return None;
    }
    let mut s = String::from("# Scheduled Tasks (Cron)\n\n");
    if ctx.cron_enabled {
        let _ = writeln!(
            s,
            "Cron is enabled with {} active job(s).",
            ctx.cron_job_count
        );
    } else {
        s.push_str(
            "Cron is not yet enabled. Enable it in daemon.toml: \
             `[cron]\\nenabled = true`\n",
        );
    }
    s.push_str(
        "\nCron jobs fire DaemonCommands on a schedule. Common pattern:\n\
         ```toml\n\
         [[cron.jobs]]\n\
         name = \"task-name\"\n\
         schedule = \"daily 10:00\"     # or \"every 30m\", \"every 2h\"\n\
         enabled = true\n\
         command = '{\"SendToAgent\": {\"name\": \"agent-name\", \
         \"text\": \"Your task\"}}'\n\
         ```\n\
         After changes: `bash: aegis daemon reload`\n",
    );
    Some(s)
}

/// Messaging / notification section. Returns None if no channel is configured.
fn build_messaging_section(ctx: &RuntimeContext) -> Option<String> {
    let channel = ctx.channel_type.as_deref()?;
    let mut s = String::from("# Messaging & Notifications\n\n");
    let _ = writeln!(
        s,
        "**{channel}** is configured as the notification channel."
    );
    s.push_str(
        "Send messages to the user from any subagent or script:\n\
         ```\n\
         bash: aegis channel send \"Your message here\"\n\
         ```\n\
         The user can also send commands back via the channel \
         (approve/deny, status, goals).\n",
    );
    Some(s)
}

/// Fleet management section. Returns None if daemon is down or no agents exist.
fn build_fleet_section(ctx: &RuntimeContext) -> Option<String> {
    if !ctx.daemon_connected || ctx.agent_count == 0 {
        return None;
    }
    let mut s = String::from("# Fleet Management\n\n");
    let _ = writeln!(
        s,
        "The daemon is managing {} agent slot(s), {} currently running.",
        ctx.agent_count, ctx.running_agent_count
    );
    s.push_str(
        "Fleet operations:\n\
         - List agents: `bash: aegis fleet list`\n\
         - Start/stop: `bash: aegis fleet start <name>` / `stop <name>`\n\
         - Send task: `bash: aegis fleet send <name> \"task description\"`\n\
         - Add agent: edit `[[agents]]` in daemon.toml, then reload\n",
    );
    Some(s)
}

/// Installed skills section. Returns None if no skills are installed.
fn build_skills_section(ctx: &RuntimeContext) -> Option<String> {
    if ctx.installed_skills.is_empty() {
        return None;
    }
    let mut s = String::from("# Installed Skills\n\n");
    s.push_str(
        "These skills are registered as `skill_*` tools in your tool list. \
         Call them directly via their tool_use names (e.g., `skill_calc`, `skill_reddit`). \
         Each runs in a sandboxed subprocess with structured JSON output. \
         Prefer skill tools over raw bash for any capability they cover.\n\n",
    );
    for skill in &ctx.installed_skills {
        if let Some(ref desc) = skill.description {
            let _ = writeln!(s, "- **{}**: {}", skill.name, desc);
        } else {
            let _ = writeln!(s, "- **{}**", skill.name);
        }
    }
    Some(s)
}

/// Subagent spawning section (always included).
fn build_subagent_section(_ctx: &RuntimeContext) -> String {
    String::from(
        "# Subagents\n\n\
         For any task too complex for a single response -- multi-step \
         workflows, file processing, code generation, audio capture, \
         data pipelines -- spawn a coding subagent via the `task` tool.\n\n\
         Subagents are full coding agent instances with bash and file tools. \
         They can:\n\
         - Run any installed CLI program (sox, whisper, ffmpeg, pdflatex, \
         pandoc, etc.)\n\
         - Write any file format (.tex, .md, .py, .sh, .json, PDFs, etc.)\n\
         - Execute multi-step workflows end-to-end\n\
         - Send notifications: `aegis channel send \"message\"`\n",
    )
}

/// Capability limits section (always included). Dynamically lists what is
/// and is not available, with setup suggestions for missing features.
fn build_capability_limits_section(ctx: &RuntimeContext) -> String {
    let mut s = String::from("# Capability Summary\n\n");

    // Available now
    s.push_str("## Available Now\n");
    s.push_str("- File read/write/edit in the workspace\n");
    s.push_str("- Shell command execution (bash) with any installed CLI tool\n");
    s.push_str("- Spawn coding subagents for parallel/complex work\n");
    if ctx.daemon_connected {
        s.push_str("- Daemon fleet management (list/start/stop agents)\n");
    }
    if ctx.cron_enabled {
        let _ = writeln!(s, "- Scheduled tasks via cron ({} active jobs)", ctx.cron_job_count);
    }
    if let Some(ref ch) = ctx.channel_type {
        let _ = writeln!(s, "- Notifications and messaging via {ch}");
    }
    if ctx.screen_capture_enabled {
        s.push_str("- Screen capture (screenshots)\n");
    }
    if ctx.input_injection_enabled {
        s.push_str("- Mouse and keyboard control\n");
    }
    if ctx.browser_enabled {
        s.push_str("- Web browser automation (CDP)\n");
    }
    if ctx.mic_capture_available {
        s.push_str("- Microphone audio capture\n");
    }
    if ctx.stt_available {
        s.push_str("- Speech-to-text transcription\n");
    }
    if ctx.tts_available {
        s.push_str("- Text-to-speech synthesis\n");
    }
    if !ctx.installed_skills.is_empty() {
        let _ = writeln!(s, "- {} installed skills", ctx.installed_skills.len());
    }

    // Not available (with setup suggestions)
    s.push_str("\n## Not Available\n");
    if !ctx.screen_capture_enabled && !ctx.input_injection_enabled {
        s.push_str("- Direct GUI interaction (toolkit not enabled in daemon.toml)\n");
    }
    if ctx.channel_type.is_none() {
        s.push_str(
            "- Notifications/messaging (no channel configured -- \
             set up Telegram or another channel in daemon.toml)\n",
        );
    }
    if !ctx.cron_enabled {
        s.push_str(
            "- Scheduled tasks (cron not enabled -- add `[cron]\\nenabled = true` \
             to daemon.toml)\n",
        );
    }
    if !ctx.daemon_connected {
        s.push_str(
            "- Fleet operations (daemon not running -- use `/daemon start`)\n",
        );
    }
    if !ctx.mic_capture_available {
        s.push_str(
            "- Audio capture (sox/arecord not found -- install sox: \
             `brew install sox` or `apt install sox`)\n",
        );
    }
    s.push_str(
        "\nIf a task requires tools or credentials not yet configured, \
         say so and tell the user exactly what to set up.\n",
    );

    s
}

/// Build the one-line runtime info string.
fn build_runtime_line(ctx: &RuntimeContext) -> String {
    let mut parts = Vec::new();
    if !ctx.hostname.is_empty() {
        parts.push(format!("host={}", ctx.hostname));
    }
    if !ctx.model.is_empty() {
        parts.push(format!("model={}", ctx.model));
    }
    if !ctx.shell.is_empty() {
        parts.push(format!("shell={}", ctx.shell));
    }
    parts.push(format!(
        "daemon={}",
        if ctx.daemon_connected {
            "connected"
        } else {
            "disconnected"
        }
    ));
    if let Some(ref ch) = ctx.channel_type {
        parts.push(format!("channel={ch}"));
    }
    // Toolkit summary
    let mut toolkit_caps = Vec::new();
    if ctx.screen_capture_enabled {
        toolkit_caps.push("capture");
    }
    if ctx.input_injection_enabled {
        toolkit_caps.push("input");
    }
    if ctx.browser_enabled {
        toolkit_caps.push("browser");
    }
    if !toolkit_caps.is_empty() {
        parts.push(format!("toolkit={}", toolkit_caps.join(",")));
    }
    if !ctx.installed_skills.is_empty() {
        parts.push(format!("skills={}", ctx.installed_skills.len()));
    }
    format!("Runtime: {}", parts.join(" | "))
}

/// Controls which sections are included in the system prompt.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PromptMode {
    /// Full prompt (main agent): all sections included.
    Full,
    /// Minimal prompt (subagents): only tooling, workspace, and runtime info.
    Minimal,
}

/// Minimal tool description for system prompt construction.
pub struct ToolDescription {
    /// Tool name (e.g. "read_file", "bash").
    pub name: String,
    /// Human-readable description of what the tool does.
    pub description: String,
}

/// Build the system prompt for chat TUI LLM requests.
///
/// Assembles modular sections in order:
/// 1. Identity (always)
/// 2. Available tools (always)
/// 3. Tool call style (full only)
/// 4. Safety (full only)
/// 5. Coding agent instructions (full only)
/// 6. apply_patch format spec (always -- subagents use it too)
/// 7. Output formatting (full only)
/// 8. Approval mode (always, if provided)
/// 9. Workspace / environment (always)
/// 10. Project context files (always)
/// 11. Git info (always)
pub fn build_system_prompt(
    tool_descriptions: &[ToolDescription],
    approval_context: Option<&str>,
    mode: PromptMode,
    runtime_context: Option<&RuntimeContext>,
) -> String {
    let is_full = mode == PromptMode::Full;
    let mut prompt = String::with_capacity(if is_full { 16384 } else { 4096 });

    // 1. Identity
    prompt.push_str(IDENTITY);

    // 2. Available tools
    if !tool_descriptions.is_empty() {
        prompt.push_str("\n# Available Tools\n\n");
        prompt.push_str("Tool names are case-sensitive. Call tools exactly as listed.\n\n");
        for tool in tool_descriptions {
            let _ = writeln!(prompt, "- **{}**: {}", tool.name, tool.description);
        }
    }

    // 3. Tool call style (full only)
    if is_full {
        prompt.push('\n');
        prompt.push_str(TOOLING_STYLE);
    }

    // 4. Safety (full only)
    if is_full {
        prompt.push('\n');
        prompt.push_str(SAFETY);
    }

    // 5. Coding agent instructions (full only)
    if is_full {
        prompt.push('\n');
        prompt.push_str(CODING);
    }

    // 5b. Capability sections (full only)
    //
    // When runtime context is available, emit conditional sections gated on
    // what's actually live. Otherwise fall back to the static capabilities.md.
    if is_full {
        if let Some(ctx) = runtime_context {
            prompt.push('\n');
            prompt.push_str(&build_self_config_section(ctx));
            for s in [
                build_toolkit_section(ctx),
                build_audio_section(ctx),
                build_cron_section(ctx),
                build_messaging_section(ctx),
                build_fleet_section(ctx),
                build_skills_section(ctx),
            ]
            .into_iter()
            .flatten()
            {
                prompt.push('\n');
                prompt.push_str(&s);
            }
            prompt.push('\n');
            prompt.push_str(&build_subagent_section(ctx));
            prompt.push('\n');
            prompt.push_str(&build_capability_limits_section(ctx));
        } else {
            prompt.push('\n');
            prompt.push_str(CAPABILITIES);
        }
    }

    // 6. apply_patch format spec (always -- subagents need it too)
    prompt.push('\n');
    prompt.push_str(APPLY_PATCH_INSTRUCTIONS);

    // 7. Output formatting (full only)
    if is_full {
        prompt.push('\n');
        prompt.push_str(OUTPUT_FORMATTING);
    }

    // 8. Approval mode
    if let Some(ctx) = approval_context {
        prompt.push_str("\n# Approval Mode\n\n");
        prompt.push_str(ctx);
        prompt.push('\n');
    }

    // 9. Workspace / environment
    prompt.push_str("\n# Workspace\n\n");
    if let Ok(cwd) = std::env::current_dir() {
        let _ = writeln!(prompt, "- Working directory: `{}`", cwd.display());
    }
    let _ = writeln!(prompt, "- OS: {}", std::env::consts::OS);
    let _ = writeln!(prompt, "- Architecture: {}", std::env::consts::ARCH);
    prompt.push_str(
        "\nTreat this directory as the workspace for file operations \
         unless explicitly instructed otherwise.\n",
    );

    // 9b. Runtime info line
    if let Some(ctx) = runtime_context {
        prompt.push_str("\n## Runtime\n\n");
        prompt.push_str(&build_runtime_line(ctx));
        prompt.push('\n');
    }

    // 10. Workspace context files (~/.aegis/workspace/)
    //
    // These are the agent's persistent identity and personality files,
    // seeded on first run and updated by the agent over time.
    // Session-type filtering: subagents only get IDENTITY.md + TOOLS.md.
    let ws = aegis_types::daemon::workspace_dir();
    let workspace_files: &[(&str, &str, bool)] = &[
        // (filename, label, full_only)
        ("SOUL.md", "SOUL.md", true), // full only -- personality
        ("IDENTITY.md", "IDENTITY.md", false), // always -- agent name
        ("USER.md", "USER.md", true), // full only -- personal
        ("TOOLS.md", "TOOLS.md", false), // always -- environment
        ("MEMORY.md", "MEMORY.md", true), // full only -- persistent memory
        ("HEARTBEAT.md", "HEARTBEAT.md", true), // full only -- session checklist
    ];

    let mut has_ws_context = false;
    let mut has_soul = false;
    let mut has_memory = false;
    let mut has_heartbeat = false;
    for &(filename, label, full_only) in workspace_files {
        if full_only && !is_full {
            continue;
        }
        let path = ws.join(filename);
        if let Some(contents) = read_file_capped(&path, MAX_FILE_CHARS) {
            if !has_ws_context {
                prompt.push_str("\n# Agent Context\n\n");
                prompt.push_str(
                    "The following workspace context files define your identity \
                     and personality. They persist across sessions.\n",
                );
                has_ws_context = true;
            }
            if filename == "SOUL.md" {
                has_soul = true;
            }
            if filename == "MEMORY.md" {
                has_memory = true;
            }
            if filename == "HEARTBEAT.md" {
                has_heartbeat = true;
            }
            let _ = writeln!(prompt, "\n## {label}\n");
            prompt.push_str(&contents);
            prompt.push('\n');
        }
    }

    // Special instruction when SOUL.md is present
    if has_soul {
        prompt.push_str(
            "\nIf SOUL.md is present above, embody its persona and tone. \
             Avoid stiff, generic replies; follow its guidance unless \
             higher-priority instructions override it.\n",
        );
    }

    // Special instruction when MEMORY.md is present
    if has_memory {
        prompt.push_str(
            "\nMEMORY.md above contains your persistent notes from prior \
             sessions. Reference it for context. Update it with new learnings \
             using write_file when you discover important information.\n",
        );
    }

    // Special instruction when HEARTBEAT.md is present
    if has_heartbeat {
        prompt.push_str(
            "\nIf HEARTBEAT.md has checklist items above, review them at the \
             start of the session. Report anything that needs attention. \
             If all items are clear, proceed normally.\n",
        );
    }

    // Bootstrap mode: when BOOTSTRAP.md exists, inject its instructions into
    // the system prompt so the agent keeps guiding setup through ALL topics
    // across multiple turns (not just the first exchange).
    if is_full {
        let bootstrap_path = ws.join("BOOTSTRAP.md");
        if let Some(bootstrap_content) = read_file_capped(&bootstrap_path, MAX_FILE_CHARS) {
            prompt.push_str("\n# Bootstrap Mode (ACTIVE)\n\n");
            prompt.push_str(
                "You are in first-run bootstrap mode. The following instructions \
                 take priority over normal conversation behavior. You MUST keep \
                 guiding the conversation through ALL topics listed below until \
                 every item is fully addressed. Do NOT move on or give up after \
                 one exchange -- ask follow-up questions for each topic. When all \
                 topics are covered and the workspace files have been updated, \
                 delete BOOTSTRAP.md using the bash tool \
                 (`rm ~/.aegis/workspace/BOOTSTRAP.md`).\n\n",
            );
            prompt.push_str(&bootstrap_content);
            prompt.push('\n');
        }
    }

    // 11. Project context files (from CWD)
    let cwd = std::env::current_dir().unwrap_or_default();
    let project_files: &[(&str, std::path::PathBuf)] = &[
        ("AGENTS.md", cwd.join("AGENTS.md")),
        ("CLAUDE.md", cwd.join("CLAUDE.md")),
        (".aegis/AGENTS.md", cwd.join(".aegis/AGENTS.md")),
    ];

    let mut has_project_context = false;
    for (label, path) in project_files {
        if let Some(contents) = read_file_capped(path, MAX_FILE_CHARS) {
            if !has_project_context {
                prompt.push_str("\n# Project Context\n\n");
                prompt.push_str("The following project context files have been loaded.\n\n");
                has_project_context = true;
            }
            let _ = writeln!(prompt, "## {label}\n");
            prompt.push_str(&contents);
            prompt.push('\n');
        }
    }

    // 12. Git info
    if let Some(git_section) = build_git_section(&cwd) {
        prompt.push_str(&git_section);
    }

    // Cap total prompt length
    if prompt.len() > MAX_PROMPT_CHARS {
        prompt.truncate(MAX_PROMPT_CHARS);
        prompt.push_str("\n\n[System prompt truncated due to length]\n");
    }

    prompt
}

/// Read a file's contents, returning `None` if it doesn't exist or can't be read.
/// Truncates at `max_chars` characters.
fn read_file_capped(path: &Path, max_chars: usize) -> Option<String> {
    let contents = std::fs::read_to_string(path).ok()?;
    if contents.len() > max_chars {
        let mut truncated = contents[..max_chars].to_string();
        truncated.push_str("\n[...truncated]");
        Some(truncated)
    } else {
        Some(contents)
    }
}

/// Build the git information section, or `None` if git is unavailable or
/// the current directory is not a git repository.
fn build_git_section(cwd: &Path) -> Option<String> {
    let branch_output = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .current_dir(cwd)
        .output()
        .ok()?;

    if !branch_output.status.success() {
        return None;
    }

    let branch = String::from_utf8_lossy(&branch_output.stdout)
        .trim()
        .to_string();

    let mut section = String::from("\n# Git Info\n\n");
    let _ = writeln!(section, "- Branch: `{branch}`");

    if let Ok(status_output) = Command::new("git")
        .args(["status", "--short"])
        .current_dir(cwd)
        .output()
    {
        if status_output.status.success() {
            let status = String::from_utf8_lossy(&status_output.stdout);
            let status = status.trim();
            if status.is_empty() {
                section.push_str("- Working tree: clean\n");
            } else {
                section.push_str("- Working tree changes:\n```\n");
                section.push_str(status);
                section.push_str("\n```\n");
            }
        }
    }

    Some(section)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_system_prompt_returns_non_empty() {
        let prompt = build_system_prompt(&[], None, PromptMode::Full, None);
        assert!(!prompt.is_empty());
    }

    #[test]
    fn prompt_contains_identity() {
        let prompt = build_system_prompt(&[], None, PromptMode::Full, None);
        assert!(prompt.contains("You are Aegis"));
        assert!(prompt.contains("autonomous coding agent"));
    }

    #[test]
    fn prompt_contains_workspace() {
        let prompt = build_system_prompt(&[], None, PromptMode::Full, None);
        assert!(prompt.contains("# Workspace"));
        assert!(prompt.contains("OS:"));
        assert!(prompt.contains("Architecture:"));
    }

    #[test]
    fn prompt_includes_tool_descriptions() {
        let tools = vec![
            ToolDescription {
                name: "read_file".into(),
                description: "Read a file from disk".into(),
            },
            ToolDescription {
                name: "bash".into(),
                description: "Run a shell command".into(),
            },
        ];
        let prompt = build_system_prompt(&tools, None, PromptMode::Full, None);
        assert!(prompt.contains("# Available Tools"));
        assert!(prompt.contains("read_file"));
        assert!(prompt.contains("Run a shell command"));
    }

    #[test]
    fn prompt_omits_tools_section_when_empty() {
        let prompt = build_system_prompt(&[], None, PromptMode::Full, None);
        assert!(!prompt.contains("# Available Tools"));
    }

    #[test]
    fn prompt_full_includes_coding_instructions() {
        let prompt = build_system_prompt(&[], None, PromptMode::Full, None);
        assert!(prompt.contains("AGENTS.md"));
        assert!(prompt.contains("Keep going until"));
        assert!(prompt.contains("apply_patch"));
    }

    #[test]
    fn prompt_full_includes_safety() {
        let prompt = build_system_prompt(&[], None, PromptMode::Full, None);
        assert!(prompt.contains("# Safety"));
        assert!(prompt.contains("self-preservation"));
    }

    #[test]
    fn prompt_full_includes_output_formatting() {
        let prompt = build_system_prompt(&[], None, PromptMode::Full, None);
        assert!(prompt.contains("# Output Formatting"));
        assert!(prompt.contains("concise"));
    }

    #[test]
    fn prompt_includes_apply_patch_format() {
        // apply_patch format is included in both modes
        let full = build_system_prompt(&[], None, PromptMode::Full, None);
        assert!(full.contains("Begin Patch"));
        assert!(full.contains("End Patch"));

        let minimal = build_system_prompt(&[], None, PromptMode::Minimal, None);
        assert!(minimal.contains("Begin Patch"));
        assert!(minimal.contains("End Patch"));
    }

    #[test]
    fn prompt_minimal_omits_full_sections() {
        let prompt = build_system_prompt(&[], None, PromptMode::Minimal, None);
        // Minimal should not include coding, safety, or output formatting
        assert!(!prompt.contains("# Coding Agent Instructions"));
        assert!(!prompt.contains("# Safety"));
        assert!(!prompt.contains("# Output Formatting"));
        assert!(!prompt.contains("# Tool Call Style"));
    }

    #[test]
    fn prompt_minimal_includes_essentials() {
        let tools = vec![ToolDescription {
            name: "bash".into(),
            description: "Run a shell command".into(),
        }];
        let prompt = build_system_prompt(&tools, Some("Full auto."), PromptMode::Minimal, None);
        // Minimal still includes identity, tools, apply_patch, workspace, approval
        assert!(prompt.contains("You are Aegis"));
        assert!(prompt.contains("# Available Tools"));
        assert!(prompt.contains("Begin Patch"));
        assert!(prompt.contains("# Workspace"));
        assert!(prompt.contains("# Approval Mode"));
        assert!(prompt.contains("Full auto."));
    }

    #[test]
    fn read_file_capped_returns_none_for_missing() {
        let result = read_file_capped(Path::new("/nonexistent/file.txt"), MAX_FILE_CHARS);
        assert!(result.is_none());
    }

    #[test]
    fn read_file_capped_truncates_long_content() {
        let dir = std::env::temp_dir().join("aegis_test_system_prompt");
        let _ = std::fs::create_dir_all(&dir);
        let file_path = dir.join("long_file.txt");
        let long_content = "x".repeat(100);
        std::fs::write(&file_path, &long_content).unwrap();

        let result = read_file_capped(&file_path, 50).unwrap();
        assert!(result.len() < long_content.len());
        assert!(result.contains("[...truncated]"));

        let _ = std::fs::remove_file(&file_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn prompt_respects_max_length() {
        let prompt = build_system_prompt(&[], None, PromptMode::Full, None);
        assert!(prompt.len() <= MAX_PROMPT_CHARS + 100);
    }

    #[test]
    fn prompt_includes_approval_context() {
        let prompt = build_system_prompt(&[], Some("All tools auto-approved."), PromptMode::Full, None);
        assert!(prompt.contains("# Approval Mode"));
        assert!(prompt.contains("All tools auto-approved."));
    }

    #[test]
    fn prompt_omits_approval_section_when_none() {
        let prompt = build_system_prompt(&[], None, PromptMode::Full, None);
        assert!(!prompt.contains("# Approval Mode"));
    }

    // -- RuntimeContext tests --

    /// Helper to build a RuntimeContext with all features disabled.
    fn bare_context() -> RuntimeContext {
        RuntimeContext {
            daemon_connected: false,
            agent_count: 0,
            running_agent_count: 0,
            channel_type: None,
            cron_enabled: false,
            cron_job_count: 0,
            screen_capture_enabled: false,
            input_injection_enabled: false,
            browser_enabled: false,
            tts_available: false,
            stt_available: false,
            mic_capture_available: false,
            installed_skills: vec![],
            hostname: "test-host".into(),
            model: "test-model".into(),
            shell: "/bin/zsh".into(),
        }
    }

    #[test]
    fn prompt_none_context_uses_static_capabilities() {
        let prompt = build_system_prompt(&[], None, PromptMode::Full, None);
        // Static capabilities.md should be included
        assert!(prompt.contains("Self-Configuration"));
        assert!(prompt.contains("Assessment Pattern"));
    }

    #[test]
    fn prompt_with_runtime_context_includes_runtime_line() {
        let ctx = bare_context();
        let prompt = build_system_prompt(&[], None, PromptMode::Full, Some(&ctx));
        assert!(prompt.contains("## Runtime"));
        assert!(prompt.contains("host=test-host"));
        assert!(prompt.contains("model=test-model"));
        assert!(prompt.contains("daemon=disconnected"));
    }

    #[test]
    fn prompt_with_all_features_enabled() {
        let mut ctx = bare_context();
        ctx.daemon_connected = true;
        ctx.agent_count = 3;
        ctx.running_agent_count = 2;
        ctx.channel_type = Some("telegram".into());
        ctx.cron_enabled = true;
        ctx.cron_job_count = 5;
        ctx.screen_capture_enabled = true;
        ctx.input_injection_enabled = true;
        ctx.browser_enabled = true;
        ctx.mic_capture_available = true;
        ctx.stt_available = true;
        ctx.tts_available = true;
        ctx.installed_skills = vec![SkillSummary {
            name: "calculator".into(),
            description: Some("Basic arithmetic".into()),
        }];

        let prompt = build_system_prompt(&[], None, PromptMode::Full, Some(&ctx));

        // All conditional sections should be present
        assert!(prompt.contains("# Computer Use"));
        assert!(prompt.contains("Screen capture"));
        assert!(prompt.contains("Input control"));
        assert!(prompt.contains("Browser automation"));
        assert!(prompt.contains("# Audio & Voice"));
        assert!(prompt.contains("Microphone capture"));
        assert!(prompt.contains("Speech-to-text"));
        assert!(prompt.contains("Text-to-speech"));
        assert!(prompt.contains("# Scheduled Tasks (Cron)"));
        assert!(prompt.contains("5 active job"));
        assert!(prompt.contains("# Messaging & Notifications"));
        assert!(prompt.contains("telegram"));
        assert!(prompt.contains("# Fleet Management"));
        assert!(prompt.contains("3 agent slot"));
        assert!(prompt.contains("# Installed Skills"));
        assert!(prompt.contains("calculator"));
        assert!(prompt.contains("Basic arithmetic"));
        assert!(prompt.contains("# Subagents"));
        assert!(prompt.contains("# Capability Summary"));
        assert!(prompt.contains("## Available Now"));
        assert!(prompt.contains("daemon=connected"));
    }

    #[test]
    fn prompt_without_channel_omits_messaging_shows_suggestion() {
        let ctx = bare_context();
        let prompt = build_system_prompt(&[], None, PromptMode::Full, Some(&ctx));
        assert!(!prompt.contains("# Messaging & Notifications"));
        assert!(prompt.contains("no channel configured"));
    }

    #[test]
    fn prompt_without_toolkit_omits_computer_use() {
        let ctx = bare_context();
        let prompt = build_system_prompt(&[], None, PromptMode::Full, Some(&ctx));
        assert!(!prompt.contains("# Computer Use"));
    }

    #[test]
    fn prompt_without_audio_omits_audio_section() {
        let ctx = bare_context();
        let prompt = build_system_prompt(&[], None, PromptMode::Full, Some(&ctx));
        assert!(!prompt.contains("# Audio & Voice"));
    }

    #[test]
    fn runtime_line_includes_toolkit_summary() {
        let mut ctx = bare_context();
        ctx.browser_enabled = true;
        ctx.screen_capture_enabled = true;
        let line = build_runtime_line(&ctx);
        assert!(line.contains("toolkit=capture,browser"));
    }

    #[test]
    fn capability_limits_lists_not_available_items() {
        let ctx = bare_context();
        let limits = build_capability_limits_section(&ctx);
        assert!(limits.contains("## Not Available"));
        assert!(limits.contains("daemon not running"));
        assert!(limits.contains("cron not enabled"));
        assert!(limits.contains("no channel configured"));
    }
}
