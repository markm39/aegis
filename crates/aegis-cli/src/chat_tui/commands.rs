//! Slash-command dispatch for the chat TUI.
//!
//! All `/command` handling is routed through `execute_command`. Private helpers
//! `handle_sandbox_command`, `run_skill_command`, and `dispatch_dynamic_skill`
//! live here to keep `ChatApp`'s impl block focused on lifecycle concerns.

use std::sync::mpsc;

use serde_json;

use aegis_control::daemon::DaemonCommand;
use aegis_types::llm::LlmMessage;
use aegis_types::tool_classification::ActionRisk;

use super::approval::ApprovalProfile;
use super::compaction;
use super::hooks;
use super::message::{ChatMessage, MessageRole};
use super::persistence;
use super::tools::{SkillCommand, SkillExecResult, SKILL_COMMANDS};
use super::ChatApp;

/// Dispatch a slash command entered by the user.
///
/// `input` is the text after the leading `/`, with surrounding whitespace trimmed
/// by the caller. Called from `ChatApp::execute_command`.
pub fn execute_command(app: &mut ChatApp, input: &str) {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return;
    }

    match trimmed {
        "quit" | "q" => {
            // Auto-save conversation if non-empty.
            if !app.conversation.is_empty() {
                let _ = persistence::save_conversation(
                    &app.session_id,
                    &app.conversation,
                    &app.model,
                );
            }
            hooks::fire_hook_event(hooks::ChatHookEvent::SessionEnd {
                session_id: app.session_id.clone(),
                message_count: app.conversation.len(),
            });
            app.running = false;
        }
        "clear" => {
            app.messages.clear();
            app.conversation.clear();
            app.scroll_offset = 0;
            app.set_result("Conversation cleared");
        }
        "save" => {
            if app.conversation.is_empty() {
                app.set_result("Nothing to save (conversation is empty).");
            } else {
                match persistence::save_conversation(
                    &app.session_id,
                    &app.conversation,
                    &app.model,
                ) {
                    Ok(()) => {
                        app.set_result(format!("Saved as {}", app.session_id));
                    }
                    Err(e) => {
                        app.set_result(format!("Failed to save: {e}"));
                    }
                }
            }
        }
        "sessions" | "list" => {
            app.open_session_picker();
        }
        "settings" => {
            app.open_settings();
        }
        "help" | "h" => {
            app.set_result(
                "/quit  /clear  /new  /compact  /abort  /model [name]  /provider  /login [provider]  /mode [auto|chat|code]  /engine [auto|provider|native]  /usage  /think  /auto  /save  /resume <id>  /sessions  /settings  /sandbox  /daemon ...  !<cmd>  |  Skills: /debug /doc /explain /refactor /test /review /security /perf /panel-review /link-worktree",
            );
        }
        "usage" => {
            let total_tokens = app.total_input_tokens + app.total_output_tokens;
            app.set_result(format!(
                "Session: {} tokens ({}in/{}out) | ${:.4}",
                total_tokens,
                app.total_input_tokens,
                app.total_output_tokens,
                app.total_cost_usd,
            ));
        }
        _ if trimmed.starts_with("model ") => {
            let input = trimmed.strip_prefix("model ").unwrap().trim();
            if input.is_empty() {
                app.show_model_info();
            } else {
                let (model_name, provider_id) = super::resolve_model_input(input);

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

                let old = app.model.clone();
                app.model = model_name.clone();
                let suffix = provider_id.map(|p| format!(" ({p})")).unwrap_or_default();
                app.set_result(format!("Model: {old} -> {model_name}{suffix}{warning}"));
            }
        }
        "model" => {
            app.open_model_picker();
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
                app.set_result(
                    "No providers available. Use /login to add credentials.",
                );
            } else {
                app.set_result(format!(
                    "Providers: {}  (use /login to manage)",
                    all.join(", ")
                ));
            }
        }
        cmd if cmd == "login" || cmd.starts_with("login ") => {
            let provider_arg = cmd.strip_prefix("login").unwrap().trim();
            if provider_arg.is_empty() {
                app.open_login(None);
            } else {
                app.open_login(Some(provider_arg));
            }
        }
        "resume" => {
            // No arg: open the session picker.
            app.open_session_picker();
        }
        _ if trimmed.starts_with("resume ") => {
            let resume_id = trimmed.strip_prefix("resume ").unwrap().trim();
            if resume_id.is_empty() {
                app.set_result("Usage: /resume <id>");
            } else {
                match persistence::load_conversation(resume_id) {
                    Ok((messages, meta)) => {
                        app.conversation = messages;
                        app.model = meta.model.clone();
                        app.session_id = meta.id.clone();
                        // New audit session for the resumed conversation.
                        app.audit_session_id = None;
                        app.register_audit_session();
                        app.rebuild_display_messages();
                        app.set_result(format!(
                            "Resumed {} ({}, {} messages)",
                            meta.id, meta.model, meta.message_count
                        ));
                    }
                    Err(e) => {
                        app.set_result(format!("Failed to resume '{resume_id}': {e}"));
                    }
                }
            }
        }
        "daemon start" => match crate::commands::daemon::start_quiet() {
            Ok(msg) => {
                app.set_result(msg);
                app.last_poll = std::time::Instant::now() - std::time::Duration::from_secs(10);
            }
            Err(e) => {
                app.last_error = Some(format!("Failed to start daemon: {e}"));
            }
        },
        "daemon stop" => {
            if !app.connected {
                app.set_result("Daemon is not running.");
            } else {
                match crate::commands::daemon::stop_quiet() {
                    Ok(msg) => {
                        app.set_result(msg);
                        app.last_poll =
                            std::time::Instant::now() - std::time::Duration::from_secs(10);
                    }
                    Err(e) => {
                        app.last_error = Some(format!("Failed to stop daemon: {e}"));
                    }
                }
            }
        }
        "daemon status" => {
            if !app.connected {
                app.set_result("Daemon is not running (offline mode).");
            } else {
                app.set_result(format!(
                    "Daemon is running. Model: {}",
                    app.model,
                ));
            }
        }
        "daemon restart" => {
            if !app.connected {
                app.set_result("Daemon is not running. Use /daemon start.");
            } else {
                match crate::commands::daemon::restart_quiet() {
                    Ok(msg) => {
                        app.set_result(msg);
                        app.last_poll =
                            std::time::Instant::now() - std::time::Duration::from_secs(10);
                    }
                    Err(e) => {
                        app.last_error = Some(format!("Failed to restart daemon: {e}"));
                    }
                }
            }
        }
        "daemon reload" => {
            if !app.connected {
                app.set_result("Daemon is not running.");
            } else {
                app.send_and_show_result(DaemonCommand::ReloadConfig);
            }
        }
        "daemon init" => match crate::commands::daemon::init_quiet() {
            Ok(msg) => app.set_result(msg),
            Err(e) => {
                app.last_error = Some(format!("{e}"));
            }
        },
        // Setup wizard commands
        "telegram setup" | "telegram" => {
            app.open_setup_wizard("telegram");
        }
        "telegram status" => {
            let msg = crate::commands::telegram::status_quiet();
            app.set_result(msg);
        }
        "telegram disable" => match crate::commands::telegram::disable_quiet() {
            Ok(msg) => app.set_result(msg),
            Err(e) => app.set_result(format!("{e}")),
        },
        _ if trimmed == "setup" => {
            let names = crate::setup_wizard::WIZARD_CHANNEL_NAMES.join(", ");
            app.set_result(format!("Usage: /setup <channel>\nAvailable: {names}"));
        }
        _ if trimmed.starts_with("setup ") => {
            let target = trimmed.strip_prefix("setup ").unwrap().trim();
            app.open_setup_wizard(target);
        }
        "new" => {
            // Fire BeforeReset hook before clearing.
            hooks::fire_hook_event(hooks::ChatHookEvent::BeforeReset {
                session_id: app.session_id.clone(),
                message_count: app.conversation.len(),
            });
            // Auto-save old conversation if non-empty.
            if !app.conversation.is_empty() {
                let _ = persistence::save_conversation(
                    &app.session_id,
                    &app.conversation,
                    &app.model,
                );
            }
            app.messages.clear();
            app.conversation.clear();
            app.scroll_offset = 0;
            app.session_id = persistence::generate_conversation_id();
            // Register a fresh audit session for the new conversation.
            app.audit_session_id = None;
            app.register_audit_session();
            // Reset token counters.
            app.total_input_tokens = 0;
            app.total_output_tokens = 0;
            app.total_cost_usd = 0.0;
            // Fire SessionStart hook for the new session.
            hooks::fire_hook_event(hooks::ChatHookEvent::SessionStart {
                session_id: app.session_id.clone(),
            });
            app.set_result("New session started");
        }
        "compact" => {
            if app.conversation.is_empty() {
                app.set_result("Nothing to compact (conversation is empty).");
            } else {
                let (estimated, threshold) =
                    compaction::should_compact(&app.conversation, &app.model);
                match compaction::compact_conversation(&app.conversation, &app.model) {
                    Some(compacted) => {
                        let old_len = app.conversation.len();
                        let new_len = compacted.len();
                        app.conversation = compacted;
                        app.rebuild_display_messages();
                        app.set_result(format!(
                            "Compacted: {} -> {} messages (~{} -> ~{} tokens)",
                            old_len, new_len, estimated, threshold,
                        ));
                    }
                    None => {
                        app.set_result(format!(
                            "No compaction needed (~{} tokens, threshold ~{})",
                            estimated, threshold,
                        ));
                    }
                }
            }
        }
        "abort" => {
            app.abort_current_request();
        }
        "think off" | "think" => {
            app.thinking_budget = None;
            app.set_result("Extended thinking disabled");
        }
        "think low" => {
            app.thinking_budget = Some(1024);
            app.set_result("Thinking budget: 1024 tokens");
        }
        "think medium" => {
            app.thinking_budget = Some(4096);
            app.set_result("Thinking budget: 4096 tokens");
        }
        "think high" => {
            app.thinking_budget = Some(16384);
            app.set_result("Thinking budget: 16384 tokens");
        }
        _ if trimmed.starts_with("think ") => {
            let arg = trimmed.strip_prefix("think ").unwrap().trim();
            match arg.parse::<u32>() {
                Ok(budget) if budget > 0 => {
                    app.thinking_budget = Some(budget);
                    app.set_result(format!("Thinking budget: {budget} tokens"));
                }
                Ok(_) => {
                    app.set_result("Thinking budget must be greater than 0");
                }
                Err(_) => {
                    app.set_result(format!(
                        "Invalid thinking budget: '{arg}'. Use a number or: off, low, medium, high"
                    ));
                }
            }
        }
        "auto off" | "auto manual" => {
            app.approval_profile = ApprovalProfile::Manual;
            app.set_result("Auto-approve: OFF (manual approval for non-safe tools)");
        }
        "auto edits" => {
            app.approval_profile = ApprovalProfile::AutoApprove(ActionRisk::Medium);
            app.set_result(
                "Auto-approve: edits + bash (up to Medium risk). Destructive commands still ask.",
            );
        }
        "auto high" => {
            app.approval_profile = ApprovalProfile::AutoApprove(ActionRisk::High);
            app.set_result("Auto-approve: up to High risk. Only Critical actions ask.");
        }
        "auto full" => {
            app.approval_profile = ApprovalProfile::FullAuto;
            app.set_result("FULL AUTO: all tools auto-approved. Use with caution.");
        }
        "auto" => {
            let current = match &app.approval_profile {
                ApprovalProfile::Manual => "manual (safe tools only)",
                ApprovalProfile::AutoApprove(ActionRisk::Medium) => {
                    "auto-edits (up to medium risk)"
                }
                ApprovalProfile::AutoApprove(ActionRisk::High) => "auto-high (up to high risk)",
                ApprovalProfile::AutoApprove(_) => "auto-custom",
                ApprovalProfile::FullAuto => "full-auto (everything)",
            };
            app.set_result(format!(
                "Current: {current}. Options: /auto off | /auto edits | /auto high | /auto full"
            ));
        }
        "heartbeat" => {
            let effective_secs = app
                .heartbeat_interval_secs
                .saturating_mul((1 + app.heartbeat_consecutive_ok).min(4) as u64);
            let since_last = app.last_heartbeat_at.elapsed().as_secs();
            app.set_result(format!(
                "Heartbeat: {} | interval: {}s (effective: {}s with {} consecutive OKs) | \
                 last: {}s ago | in-flight: {}",
                if app.heartbeat_enabled { "ON" } else { "OFF" },
                app.heartbeat_interval_secs,
                effective_secs,
                app.heartbeat_consecutive_ok,
                since_last,
                app.heartbeat_in_flight,
            ));
        }
        "heartbeat now" => {
            app.heartbeat_wake_pending = true;
            app.set_result("Heartbeat will fire on next tick.");
        }
        "heartbeat on" => {
            app.heartbeat_enabled = true;
            app.set_result("Heartbeat enabled.");
        }
        "heartbeat off" => {
            app.heartbeat_enabled = false;
            app.set_result("Heartbeat disabled.");
        }
        _ if trimmed.starts_with("heartbeat interval ") => {
            let arg = trimmed
                .strip_prefix("heartbeat interval ")
                .unwrap()
                .trim();
            match arg.parse::<u64>() {
                Ok(secs) if secs >= 30 => {
                    app.heartbeat_interval_secs = secs;
                    app.heartbeat_consecutive_ok = 0; // Reset backoff.
                    app.set_result(format!("Heartbeat interval set to {secs}s."));
                }
                Ok(_) => {
                    app.set_result("Minimum heartbeat interval is 30 seconds.");
                }
                Err(_) => {
                    app.set_result(format!(
                        "Invalid interval: '{arg}'. Use seconds (e.g. /heartbeat interval 300)"
                    ));
                }
            }
        }
        "sandbox" => {
            handle_sandbox_command(app);
        }
        other => {
            // 1. Check hardcoded prompt-based skill commands.
            if let Some(skill_cmd) = SKILL_COMMANDS
                .iter()
                .find(|sc| other == sc.name || other.starts_with(&format!("{} ", sc.name)))
            {
                let arg = other.strip_prefix(skill_cmd.name).unwrap_or("").trim();
                if arg.is_empty() && skill_cmd.needs_arg {
                    app.set_result(skill_cmd.arg_hint);
                } else {
                    run_skill_command(app, skill_cmd, arg);
                }
                return;
            }
            // 2. Check dynamic skill router for registered slash commands.
            let cmd_name = other.split_whitespace().next().unwrap_or("");
            if app.skill_router.route_name(cmd_name).is_some() {
                dispatch_dynamic_skill(app, other);
                return;
            }
            app.set_result(format!(
                "Unknown command: '{other}'. Type /help for commands."
            ));
        }
    }
}

/// Start the LLM-guided sandbox configuration conversation.
///
/// Injects an opening user message that causes the LLM to interview the user
/// about network access, filesystem paths, and isolation level, then produce
/// a JSON config block that can be applied to daemon.toml.
fn handle_sandbox_command(app: &mut ChatApp) {
    const SANDBOX_OPENING: &str = "\
I need help configuring the Aegis sandbox security rules for my AI coding agent. \
Please ask me about what network hosts the agent needs access to, what filesystem \
paths it should be able to write to beyond the project directory, and what isolation \
level makes sense (macOS Seatbelt, Docker, process-level policy, or none). \
When you have gathered enough information, output a JSON configuration block in this format:
```json
{
  \"isolation\": \"seatbelt\",
  \"allowed_hosts\": [\"api.anthropic.com\"],
  \"extra_write_paths\": []
}
```
Start by asking your first question.";

    app.conversation.push(LlmMessage::user(SANDBOX_OPENING.to_string()));
    app.messages
        .push(ChatMessage::new(MessageRole::User, "/sandbox".to_string()));
    app.scroll_offset = 0;
    app.awaiting_response = true;
    app.send_llm_request();
}

/// Execute a skill command by injecting its prompt into the conversation.
///
/// Replaces `$ARGUMENTS` in the prompt template with the user's argument,
/// adds it as a user message, and triggers an LLM request. The user sees
/// a compact `/command arg` display message while the LLM sees the full
/// expanded prompt.
fn run_skill_command(app: &mut ChatApp, cmd: &SkillCommand, arg: &str) {
    let prompt = cmd.prompt.replace("$ARGUMENTS", arg);

    app.conversation.push(LlmMessage::user(prompt));

    let display = if arg.is_empty() {
        format!("/{}", cmd.name)
    } else {
        format!("/{} {}", cmd.name, arg)
    };
    app.messages
        .push(ChatMessage::new(MessageRole::User, display));
    app.scroll_offset = 0;
    app.awaiting_response = true;
    app.send_llm_request();
}

/// Dispatch a dynamic skill command via the SkillExecutor.
///
/// Parses the command, looks up the skill in the router/registry,
/// spawns a background thread with a tokio runtime to run the async
/// executor, and sends the result back via a channel.
fn dispatch_dynamic_skill(app: &mut ChatApp, input: &str) {
    let parts: Vec<&str> = input.splitn(2, ' ').collect();
    let cmd_name = parts[0].to_string();
    let args_raw = parts.get(1).copied().unwrap_or("").to_string();

    let skill_name = match app.skill_router.route_name(&cmd_name) {
        Some(name) => name.to_string(),
        None => {
            app.set_result(format!("No skill registered for /{cmd_name}"));
            return;
        }
    };

    let instance = match app.skill_registry.get(&skill_name) {
        Some(i) => i,
        None => {
            app.set_result(format!("Skill '{skill_name}' not in registry"));
            return;
        }
    };

    let manifest = instance.manifest.clone();
    let skill_dir = instance.path.clone();

    // Show the command in the chat.
    app.messages.push(ChatMessage::new(
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
        session_id: Some(app.session_id.clone()),
        workspace_path: None,
        env_vars: Default::default(),
    };

    let (tx, rx) = mpsc::channel();
    app.skill_result_rx = Some(rx);

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
