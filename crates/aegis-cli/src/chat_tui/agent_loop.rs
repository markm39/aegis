//! Background agentic loop: LLM calls, tool execution, subagent spawning.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;

use aegis_control::daemon::{DaemonClient, DaemonCommand, DaemonResponse};
use aegis_types::llm::{LlmMessage, LlmResponse, StopReason};

use super::approval::{ApprovalProfile, approval_context_for_prompt, should_auto_approve_tool};
use super::hooks;
use super::streaming;
use super::system_prompt::PromptMode;
use super::tools::{
    build_tool_definitions, get_tool_descriptions, summarize_tool_input,
};

/// Timeout for LLM completion requests (seconds).
/// LLM responses can take a while, so this is much longer than the default
/// 5-second DaemonClient timeout.
pub const LLM_TIMEOUT_SECS: u64 = 120;

/// Global counter for background task IDs.
pub static NEXT_TASK_ID: AtomicUsize = AtomicUsize::new(1);

/// Which coding CLI backend to use for subagent spawning.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SubagentBackend {
    /// Claude Code CLI (`claude --dangerously-skip-permissions -p "prompt"`).
    ClaudeCode,
    /// OpenAI Codex CLI (`codex --full-auto -p "prompt"`).
    Codex,
    /// No external CLI found; fall back to nested LLM loop.
    LlmFallback,
}

/// Detect and cache the best available coding CLI. Checked via `which`.
static SUBAGENT_BACKEND: std::sync::OnceLock<SubagentBackend> = std::sync::OnceLock::new();

pub fn detect_subagent_backend() -> SubagentBackend {
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

/// Incremental events from the agentic loop running in a background thread.
pub enum AgentLoopEvent {
    /// LLM returned a text response (final -- loop ended).
    Response(LlmResponse),
    /// Incremental text from a streaming LLM response.
    StreamDelta(String),
    /// Incremental thinking text from a streaming LLM response (e.g., MiniMax).
    StreamThinking(String),
    /// LLM wants to call tools -- display them to the user.
    ToolCalls(Vec<aegis_types::llm::LlmToolCall>),
    /// A tool finished executing -- display the result.
    ToolResult {
        tool_call_id: String,
        tool_name: String,
        result: String,
    },
    /// LLM needs approval for a tool before executing it.
    ToolApprovalNeeded {
        tool_call: aegis_types::llm::LlmToolCall,
    },
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

/// Parameters for `run_agent_loop`, grouped to stay under clippy's argument limit.
pub struct AgentLoopParams {
    pub socket_path: std::path::PathBuf,
    pub conversation: Vec<LlmMessage>,
    pub model: String,
    pub sys_prompt: String,
    pub tool_defs: Option<serde_json::Value>,
    pub auto_approve: bool,
    pub approval_profile: ApprovalProfile,
    pub thinking_budget: Option<u32>,
    /// Audit ledger session UUID for tool execution linkage.
    pub audit_session_id: Option<String>,
    /// Flag checked between iterations -- if true, the loop exits early.
    pub abort_flag: Arc<AtomicBool>,
    /// Skill registry snapshot for executing skill_* tool calls.
    pub skill_manifests: Vec<(String, aegis_skills::SkillManifest, std::path::PathBuf)>,
}

/// Run the agentic loop in a background thread.
///
/// Sends the conversation + tools to the LLM, and if the LLM returns tool
/// calls, executes them and loops. Safe tools are auto-approved; dangerous
/// tools require user approval via the `approval_rx` channel.
pub fn run_agent_loop(
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
                execute_task_tool(tc, &params, &event_tx, auto_approve_all)
            } else if tc.name.starts_with("skill_") {
                execute_skill_tool(tc, &params)
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

/// Execute a `task` tool call -- dispatches to subagent based on preferences.
fn execute_task_tool(
    tc: &aegis_types::llm::LlmToolCall,
    params: &AgentLoopParams,
    event_tx: &mpsc::Sender<AgentLoopEvent>,
    _auto_approve_all: bool,
) -> Result<String, String> {
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
                run_background_task(params, desc, prompt, event_tx)
            } else {
                let _ = event_tx.send(AgentLoopEvent::StreamDelta(format!(
                    "\n  [Task: {desc} (LLM) ...]\n"
                )));
                run_subagent_task(params, prompt, event_tx)
            }
        }
        Ok(backend) => {
            let _ = event_tx.send(AgentLoopEvent::StreamDelta(format!(
                "\n  [Task: {desc} ({backend:?}) ...]\n"
            )));
            let result = if background {
                run_background_pilot_task(desc, prompt, event_tx, backend, &params.abort_flag)
            } else {
                run_pilot_subagent(prompt, event_tx, backend, &params.abort_flag)
            };
            // Fall back to LLM loop if pilot spawn fails.
            match result {
                Ok(output) => Ok(output),
                Err(e) => {
                    let _ = event_tx.send(AgentLoopEvent::StreamDelta(format!(
                        "  [Subagent spawn failed: {e}. Falling back to LLM loop.]\n"
                    )));
                    if background {
                        run_background_task(params, desc, prompt, event_tx)
                    } else {
                        run_subagent_task(params, prompt, event_tx)
                    }
                }
            }
        }
    }
}

/// Execute a `skill_*` tool call via the SkillExecutor.
fn execute_skill_tool(
    tc: &aegis_types::llm::LlmToolCall,
    params: &AgentLoopParams,
) -> Result<String, String> {
    let cmd_name = tc.name.strip_prefix("skill_").unwrap_or(&tc.name);
    let args_str = tc
        .input
        .get("args")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let args: Vec<String> = args_str.split_whitespace().map(String::from).collect();

    // Find the skill that owns this command.
    let skill_match = params.skill_manifests.iter().find(|(_, manifest, _)| {
        manifest
            .commands
            .as_ref()
            .is_some_and(|cmds| cmds.iter().any(|c| c.name == cmd_name))
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
                                    serde_json::to_string(&output.result).unwrap_or_default()
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
}

/// Attempt a streaming LLM call. Returns `Err` if the model doesn't support
/// streaming (caller should fall back to the daemon's blocking path).
pub fn try_streaming_call(
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
pub fn parse_llm_response(
    result: Result<DaemonResponse, String>,
) -> Result<LlmResponse, String> {
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
pub fn execute_tool_via_daemon(
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
pub fn run_subagent_task(
    params: &AgentLoopParams,
    task_prompt: &str,
    event_tx: &mpsc::Sender<AgentLoopEvent>,
) -> Result<String, String> {
    let mut conversation = vec![LlmMessage::user(task_prompt)];

    // Build subagent tools (everything except "task" -- no recursive spawning).
    // Subagents don't get skill tools -- they use bash directly for simplicity.
    let empty_registry = aegis_skills::SkillRegistry::new();
    let tool_descs: Vec<super::system_prompt::ToolDescription> = get_tool_descriptions(&empty_registry)
        .into_iter()
        .filter(|t| t.name != "task")
        .collect();
    let sys_prompt = super::system_prompt::build_system_prompt(
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
pub fn run_background_task(
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
pub fn run_pilot_subagent(
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
    let mut adapter: Box<dyn aegis_pilot::adapter::AgentAdapter> = match driver.create_adapter() {
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
pub fn run_background_pilot_task(
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
pub fn send_with_timeout(
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

    let mut json = serde_json::to_string(command)
        .map_err(|e| format!("failed to serialize command: {e}"))?;
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
