//! DaemonRuntime constructor and helper methods.
//!
//! Contains `new()`, `ensure_channel_session`, capture stream management,
//! subagent lifecycle helpers, and audit store helpers.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tracing::{info, warn};

use aegis_control::alias::AliasRegistry;
use aegis_control::daemon::{
    CaptureSessionStarted, RuntimeAuditProvenance, RuntimeOperation, SpawnSubagentRequest,
    SpawnSubagentResult,
};
use aegis_ledger::{AuditStore, PiiRedactor};
use aegis_toolkit::contract::CaptureRegion as ToolkitCaptureRegion;
use aegis_toolkit::contract::ToolAction;
use aegis_toolkit::policy::map_tool_action;
use aegis_types::daemon::{AgentSlotConfig, AgentToolConfig, DaemonConfig, RestartPolicy};
use aegis_types::{AegisConfig, AegisError};
use aegis_types::{Action, ActionKind, Decision, Verdict};

use crate::capture::{
    CachedFrame, CaptureStream, FrameRing, SubagentSession, CAPTURE_DEFAULT_FPS,
    DEFAULT_SUBAGENT_DEPTH_LIMIT, FRAME_RING_CAPACITY,
};
use crate::channel_session::{
    channel_generate_conversation_id, channel_list_conversations,
    channel_load_conversation,
};
use crate::fleet::Fleet;
use crate::toolkit_runtime::ToolkitRuntime;
use crate::DaemonRuntime;

impl DaemonRuntime {
    /// Create a new daemon runtime from configuration.
    pub fn new(config: DaemonConfig, aegis_config: AegisConfig) -> Self {
        // Build the shared runtime first so the handle can be injected into
        // all subsystems (fleet, control socket, dashboard, tool execution).
        let tokio_rt = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .thread_name("aegis-async")
                .enable_all()
                .build()
                .expect("failed to create shared tokio runtime"),
        );

        let mut fleet = Fleet::new(&config, aegis_config.clone());
        fleet.set_rt_handle(tokio_rt.handle().clone());

        // Load Cedar policy engine for hook-based tool use evaluation.
        // Only loads if a policy directory exists AND contains .cedar files.
        // If unavailable, hook checks fail-closed unless explicitly
        // configured fail-open via AEGIS_HOOK_FAIL_OPEN.
        let policy_engine = aegis_config
            .policy_paths
            .first()
            .filter(|dir| {
                dir.is_dir()
                    && std::fs::read_dir(dir)
                        .ok()
                        .map(|entries| {
                            entries
                                .filter_map(|e| e.ok())
                                .any(|e| e.path().extension().is_some_and(|ext| ext == "cedar"))
                        })
                        .unwrap_or(false)
            })
            .and_then(|dir| match aegis_policy::PolicyEngine::new(dir, None) {
                Ok(engine) => {
                    info!(policy_dir = %dir.display(), "loaded Cedar policy engine for hooks");
                    Some(engine)
                }
                Err(e) => {
                    warn!(
                        ?e,
                        "no Cedar policy engine loaded (hook checks will fail-closed)"
                    );
                    None
                }
            });

        let alias_registry = AliasRegistry::from_config(&config.aliases);

        let mut cmd_registry = crate::commands::CommandRegistry::new();
        crate::commands::register_builtins(&mut cmd_registry);
        let command_router = crate::commands::CommandRouter::new(
            cmd_registry,
            // Default permission checker: allow all commands.
            // In production, this would delegate to Cedar policy evaluation.
            Box::new(|_action, _principal| true),
        );

        // Initialize device registry alongside the audit ledger.
        let device_store = {
            let db_path = aegis_config
                .ledger_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("devices.db");
            match crate::device_registry::DeviceStore::open(&db_path) {
                Ok(store) => {
                    info!(db_path = %db_path.display(), "device registry initialized");
                    Some(store)
                }
                Err(e) => {
                    warn!(error = %e, "failed to initialize device registry, pairing disabled");
                    None
                }
            }
        };

        // Initialize memory store if enabled.
        let memory_store = if config.memory.enabled {
            let daemon_dir = aegis_config
                .ledger_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."));
            let db_path = config
                .memory
                .db_path
                .as_deref()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| daemon_dir.join("memory.db"));
            if let Some(parent) = db_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            match crate::memory::MemoryStore::new(&db_path) {
                Ok(store) => {
                    info!(db_path = %db_path.display(), "memory store initialized");
                    Some(store)
                }
                Err(e) => {
                    warn!(error = %e, "failed to initialize memory store");
                    None
                }
            }
        } else {
            None
        };

        // Initialize cron scheduler from config.
        let cron_scheduler = {
            let jobs: Vec<crate::cron::CronJob> = config
                .cron
                .jobs
                .iter()
                .filter_map(|jc| {
                    let schedule = match crate::cron::Schedule::parse(&jc.schedule) {
                        Ok(s) => s,
                        Err(e) => {
                            warn!(name = %jc.name, error = %e, "skipping cron job with invalid schedule");
                            return None;
                        }
                    };
                    Some(crate::cron::CronJob {
                        name: jc.name.clone(),
                        schedule,
                        command: jc.command.clone(),
                        enabled: jc.enabled,
                    })
                })
                .collect();
            let count = jobs.len();
            let scheduler = crate::cron::CronScheduler::new(jobs);
            if count > 0 {
                info!(count, "cron scheduler initialized with pre-configured jobs");
            }
            scheduler
        };

        // Initialize heartbeat runner from config.
        let heartbeat_runner = {
            let hb_config = crate::heartbeat::HeartbeatRunnerConfig {
                interval: Duration::from_secs(config.heartbeat.interval_secs),
                enabled: config.heartbeat.enabled,
            };
            if let Err(e) = crate::heartbeat::validate_interval(hb_config.interval) {
                warn!(error = %e, "invalid heartbeat interval, using default (60s)");
                crate::heartbeat::HeartbeatRunner::new(
                    crate::heartbeat::HeartbeatRunnerConfig::default(),
                )
            } else {
                crate::heartbeat::HeartbeatRunner::new(hb_config)
            }
        };

        // Initialize deferred reply queue with persistence.
        let deferred_reply_queue = {
            let daemon_dir = aegis_config
                .ledger_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."));
            let queue_path = daemon_dir.join("deferred_replies.json");
            match crate::deferred_reply::DeferredReplyQueue::with_persistence(&queue_path) {
                Ok(queue) => queue,
                Err(e) => {
                    warn!(error = %e, "failed to load deferred replies, starting empty");
                    crate::deferred_reply::DeferredReplyQueue::new()
                }
            }
        };

        // Discover plugins if enabled.
        let plugin_registry = {
            let aegis_dir = aegis_config
                .ledger_path
                .parent()
                .and_then(|p| p.parent())
                .unwrap_or_else(|| std::path::Path::new("."));
            let plugin_dir = config
                .plugins
                .plugin_dir
                .as_deref()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| aegis_dir.join("plugins"));
            if config.plugins.enabled && plugin_dir.is_dir() {
                match crate::plugins::PluginRegistry::discover(&plugin_dir) {
                    Ok(registry) => {
                        info!(
                            plugin_dir = %plugin_dir.display(),
                            count = registry.list().len(),
                            "plugin registry initialized"
                        );
                        registry
                    }
                    Err(e) => {
                        warn!(error = %e, "failed to discover plugins, starting with empty registry");
                        crate::plugins::PluginRegistry::new()
                    }
                }
            } else {
                crate::plugins::PluginRegistry::new()
            }
        };

        // Initialize auto-reply store.
        let auto_reply_store = {
            let daemon_dir = aegis_config
                .ledger_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."));
            let db_path = daemon_dir.join("auto_replies.db");
            if let Some(parent) = db_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            match aegis_channel::auto_reply::AutoReplyStore::open(&db_path) {
                Ok(store) => {
                    info!(db_path = %db_path.display(), "auto-reply store initialized");
                    Some(store)
                }
                Err(e) => {
                    warn!(error = %e, "failed to initialize auto-reply store");
                    None
                }
            }
        };

        // Open push subscription store alongside other daemon databases.
        let push_store = {
            let push_db = aegis_config
                .ledger_path
                .parent()
                .unwrap_or(std::path::Path::new("."))
                .join("push_subscriptions.db");
            match aegis_alert::push::PushSubscriptionStore::open(&push_db.to_string_lossy()) {
                Ok(store) => {
                    info!(path = %push_db.display(), "push subscription store opened");
                    Some(store)
                }
                Err(e) => {
                    warn!(error = %e, "failed to open push subscription store");
                    None
                }
            }
        };

        // Spawn alert dispatcher thread if alert rules are configured.
        let (alert_tx, alert_thread) = if !config.alerts.is_empty() {
            let (tx, rx) = std::sync::mpsc::sync_channel(256);
            let push_db = aegis_config
                .ledger_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("push_subscriptions.db");
            let dispatcher_config = aegis_alert::dispatcher::DispatcherConfig {
                rules: config.alerts.clone(),
                config_name: aegis_config.name.clone(),
                db_path: aegis_config.ledger_path.to_string_lossy().into_owned(),
                push_db_path: Some(push_db.to_string_lossy().into_owned()),
                vapid_config: None,
            };
            match std::thread::Builder::new()
                .name("aegis-alert-dispatcher".into())
                .spawn(move || {
                    aegis_alert::dispatcher::run(dispatcher_config, rx);
                }) {
                Ok(handle) => {
                    info!(rules = config.alerts.len(), "alert dispatcher started");
                    (Some(tx), Some(handle))
                }
                Err(e) => {
                    warn!(error = %e, "failed to spawn alert dispatcher thread");
                    (None, None)
                }
            }
        } else {
            (None, None)
        };

        Self {
            tokio_rt,
            fleet,
            config,
            shutdown: Arc::new(AtomicBool::new(false)),
            started_at: Instant::now(),
            channel_tx: None,
            channel_cmd_rx: None,
            channel_chat_history: Vec::new(),
            channel_session_id: None,
            channel_system_prompt: None,
            // NOTE: channel session is loaded lazily on first ChannelChat command
            // to avoid blocking the constructor.
            channel_heartbeat_last: Instant::now(),
            channel_heartbeat_consecutive_ok: 0,
            channel_heartbeat_last_text: None,
            channel_thread: None,
            policy_engine,
            aegis_config,
            capture_sessions: std::collections::HashMap::new(),
            capture_streams: std::collections::HashMap::new(),
            last_tool_actions: std::collections::HashMap::new(),
            toolkit_runtime: None,
            subagents: std::collections::HashMap::new(),
            dashboard_listen: None,
            dashboard_token: None,
            heartbeat_last_sent: std::collections::HashMap::new(),
            alias_registry,
            command_router,
            scheduled_reply_mgr: crate::scheduled_reply::ScheduledReplyManager::new(),
            message_router: crate::message_routing::MessageRouter::new(),
            job_tracker: crate::jobs::JobTracker::new(),
            command_queue: crate::command_queue::CommandQueue::new(),
            setup_code_manager: device_store
                .as_ref()
                .map(|store| crate::setup_codes::SetupCodeManager::new(store.hmac_key().to_vec())),
            device_store,
            phone_controller: crate::phone_control::PhoneController::new(),
            voice_manager: None, // Initialized lazily if TWILIO_AUTH_TOKEN is set
            speech_manager: None, // Initialized lazily if DEEPGRAM_API_KEY or OPENAI_API_KEY is set
            voice_gateway: crate::voice_gateway::VoiceGateway::new(),
            tool_registry: {
                let registry = aegis_tools::ToolRegistry::new();
                match crate::builtin_tools::register_builtins(&registry) {
                    Ok(()) => {
                        info!(
                            count = registry.tool_count(),
                            "builtin tool registry initialized"
                        );
                        Some(registry)
                    }
                    Err(e) => {
                        warn!(error = %e, "failed to initialize builtin tool registry");
                        None
                    }
                }
            },
            llm_client: match crate::llm_client::build_registry_from_env() {
                Ok(registry) => match crate::llm_client::LlmClient::new(registry) {
                    Ok(client) => {
                        info!("LLM client initialized (Anthropic + OpenAI providers)");
                        Some(client)
                    }
                    Err(e) => {
                        warn!(error = %e, "failed to initialize LLM client");
                        None
                    }
                },
                Err(e) => {
                    warn!(error = %e, "failed to build LLM provider registry");
                    None
                }
            },
            memory_store,
            cron_scheduler,
            plugin_registry,
            auto_reply_store,
            poll_manager: aegis_channel::polls::PollManager::new(),
            model_allowlist: Vec::new(),
            push_store,
            push_rate_limiter: aegis_alert::push::PushRateLimiter::new(60),
            last_retention_check: Instant::now(),
            alert_tx,
            alert_thread,
            heartbeat_runner,
            deferred_reply_queue,
        }
    }

    /// Ensure the channel session is loaded. On first call, loads the most
    /// recent conversation from ~/.aegis/conversations/. On subsequent calls
    /// this is a no-op (session already loaded).
    pub(crate) fn ensure_channel_session(&mut self) {
        if self.channel_session_id.is_some() {
            return;
        }
        // Try to load most recent conversation.
        let conversations = channel_list_conversations();
        if let Some(most_recent) = conversations.first() {
            if let Some((messages, meta)) = channel_load_conversation(&most_recent.id) {
                info!(
                    session_id = %meta.id,
                    messages = messages.len(),
                    "resumed most recent channel session"
                );
                self.channel_chat_history = messages;
                self.channel_session_id = Some(meta.id);
                return;
            }
        }
        // No existing session -- create a fresh one.
        let id = channel_generate_conversation_id();
        info!(session_id = %id, "created new channel session");
        self.channel_session_id = Some(id);
    }

    pub(crate) fn stop_capture_stream(&mut self, name: &str) {
        if let Some(stream) = self.capture_streams.remove(name) {
            stream.stop.store(true, Ordering::Relaxed);
            let _ = stream.handle.join();
        }
    }

    pub(crate) fn stop_all_capture_streams(&mut self) {
        let names: Vec<String> = self.capture_streams.keys().cloned().collect();
        for name in names {
            self.stop_capture_stream(&name);
        }
    }

    pub(crate) fn subagent_depth(&self, name: &str) -> u8 {
        self.subagents.get(name).map(|s| s.depth).unwrap_or(0)
    }

    pub(crate) fn generated_subagent_name(parent: &str) -> String {
        let id = uuid::Uuid::new_v4().simple().to_string();
        format!("{parent}-sub-{}", &id[..8])
    }

    pub(crate) fn restrict_subagent_tool(tool: &AgentToolConfig) -> Result<AgentToolConfig, String> {
        match tool {
            AgentToolConfig::ClaudeCode { .. } => Ok(AgentToolConfig::ClaudeCode {
                skip_permissions: false,
                one_shot: false,
                extra_args: Vec::new(),
            }),
            AgentToolConfig::Codex { runtime_engine, .. } => Ok(AgentToolConfig::Codex {
                runtime_engine: runtime_engine.clone(),
                approval_mode: "suggest".to_string(),
                one_shot: false,
                extra_args: Vec::new(),
            }),
            AgentToolConfig::OpenClaw { agent_name, .. } => Ok(AgentToolConfig::OpenClaw {
                agent_name: agent_name.clone(),
                extra_args: Vec::new(),
            }),
            AgentToolConfig::Custom { .. } => Err(
                "custom tool subagent spawn is blocked; configure a bounded first-party tool runtime"
                    .to_string(),
            ),
        }
    }

    /// Open an [`AuditStore`] with the daemon's PII redaction config applied.
    pub(crate) fn open_audit_store(&self) -> Result<AuditStore, AegisError> {
        let mut store = AuditStore::open(&self.aegis_config.ledger_path)?;
        match PiiRedactor::from_config(&self.config.redaction) {
            Ok(redactor) => store.set_redactor(redactor),
            Err(e) => {
                warn!(error = %e, "invalid redaction config; proceeding without redaction");
            }
        }
        if let Some(ref tx) = self.alert_tx {
            store.set_alert_sender(tx.clone());
        }
        Ok(store)
    }

    pub(crate) fn append_audit_entry(&self, action: &Action, verdict: &Verdict) {
        match self.open_audit_store() {
            Ok(mut store) => {
                if let Err(e) = store.append(action, verdict) {
                    warn!(?e, "failed to append audit entry");
                }
            }
            Err(e) => {
                warn!(?e, "failed to open audit ledger");
            }
        }
    }

    pub(crate) fn authorize_subagent_spawn(
        &self,
        request: &SpawnSubagentRequest,
        child_depth: u8,
    ) -> Result<(), String> {
        let action = Action::new(
            request.parent.clone(),
            ActionKind::ToolCall {
                tool: "SubagentSpawn".to_string(),
                args: serde_json::json!({
                    "parent": request.parent.clone(),
                    "name": request.name.clone(),
                    "role": request.role.clone(),
                    "task": request.task.clone(),
                    "depth_limit": request.depth_limit,
                    "start": request.start,
                    "child_depth": child_depth,
                }),
            },
        );

        let (decision, reason) = match &self.policy_engine {
            Some(engine) => {
                let verdict = engine.evaluate(&action);
                (verdict.decision, verdict.reason)
            }
            None => (
                Decision::Deny,
                "policy engine unavailable; denied by fail-closed subagent policy".to_string(),
            ),
        };

        let verdict = match decision {
            Decision::Allow => Verdict::allow(action.id, reason.clone(), None),
            Decision::Deny => Verdict::deny(action.id, reason.clone(), None),
        };
        self.append_audit_entry(&action, &verdict);

        match decision {
            Decision::Allow => Ok(()),
            Decision::Deny => Err(reason),
        }
    }

    pub(crate) fn collect_subagent_descendants(&self, root: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut queue = VecDeque::new();
        queue.push_back(root.to_string());
        while let Some(parent) = queue.pop_front() {
            let mut children: Vec<String> = self
                .subagents
                .iter()
                .filter(|(_, meta)| meta.parent == parent)
                .map(|(child, _)| child.clone())
                .collect();
            children.sort();
            for child in children {
                queue.push_back(child.clone());
                out.push(child);
            }
        }
        out
    }

    pub(crate) fn cleanup_agent_runtime_state(&mut self, name: &str) {
        self.stop_capture_stream(name);
        self.capture_sessions.remove(name);
        self.last_tool_actions.remove(name);
        self.heartbeat_runner.unregister_agent(name);
    }

    pub(crate) fn remove_subagent_descendants(&mut self, root: &str) {
        let descendants = self.collect_subagent_descendants(root);
        for child in descendants.into_iter().rev() {
            self.cleanup_agent_runtime_state(&child);
            self.fleet.remove_agent(&child);
            self.subagents.remove(&child);
        }
    }

    pub(crate) fn spawn_subagent(
        &mut self,
        request: SpawnSubagentRequest,
    ) -> Result<SpawnSubagentResult, String> {
        let parent = request.parent.trim();
        if parent.is_empty() {
            return Err("parent agent name is required".to_string());
        }
        if self.fleet.slot(parent).is_none() {
            return Err(format!("unknown parent agent: {parent}"));
        }

        let parent_config = self
            .fleet
            .slot(parent)
            .map(|slot| slot.config.clone())
            .ok_or_else(|| format!("unknown parent agent: {parent}"))?;
        let parent_is_subagent = self.subagents.contains_key(parent);
        let parent_is_orchestrator = parent_config.orchestrator.is_some();
        if !parent_is_orchestrator && !parent_is_subagent {
            return Err(format!(
                "parent '{parent}' is not an orchestrator/subagent; subagent spawn denied"
            ));
        }

        let depth_limit = request.depth_limit.unwrap_or(DEFAULT_SUBAGENT_DEPTH_LIMIT);
        if depth_limit == 0 {
            return Err("depth_limit must be >= 1".to_string());
        }
        let child_depth = self.subagent_depth(parent).saturating_add(1);
        if child_depth > depth_limit {
            return Err(format!(
                "subagent depth {child_depth} exceeds depth_limit {depth_limit}"
            ));
        }

        let child_name = request
            .name
            .as_deref()
            .filter(|n| !n.trim().is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| Self::generated_subagent_name(parent));
        if let Err(e) = aegis_types::validate_config_name(&child_name) {
            return Err(format!("invalid subagent name: {e}"));
        }
        if self.fleet.agent_status(&child_name).is_some() {
            return Err(format!("agent '{child_name}' already exists"));
        }

        self.authorize_subagent_spawn(&request, child_depth)?;

        let working_dir = parent_config
            .working_dir
            .join(".aegis")
            .join("subagents")
            .join(&child_name);
        std::fs::create_dir_all(&working_dir)
            .map_err(|e| format!("failed to create subagent workspace: {e}"))?;

        let tool = Self::restrict_subagent_tool(&parent_config.tool)?;
        let context = match parent_config.context.as_deref() {
            Some(existing) if !existing.trim().is_empty() => Some(format!(
                "{existing}\n\nSubagent constraints: stay within workspace {} and follow parent '{parent}' directives.",
                working_dir.display()
            )),
            _ => Some(format!(
                "Subagent constraints: stay within workspace {} and follow parent '{parent}' directives.",
                working_dir.display()
            )),
        };

        let child_config = AgentSlotConfig {
            name: child_name.clone().into(),
            tool: tool.clone(),
            working_dir: working_dir.clone(),
            role: request
                .role
                .clone()
                .or_else(|| Some(format!("Subagent for {parent}"))),
            agent_goal: parent_config.agent_goal.clone(),
            context,
            task: request.task.clone().or_else(|| parent_config.task.clone()),
            pilot: parent_config.pilot.clone(),
            restart: RestartPolicy::Never,
            max_restarts: 0,
            enabled: true,
            orchestrator: None,
            security_preset: parent_config.security_preset.clone(),
            policy_dir: parent_config.policy_dir.clone(),
            isolation: parent_config.isolation.clone(),
            lane: parent_config.lane.clone(),
        };

        self.fleet.add_agent(child_config);
        if request.start {
            self.fleet.start_agent(&child_name);
            self.heartbeat_runner.register_agent(&child_name);
        }
        self.subagents.insert(
            child_name.clone(),
            SubagentSession {
                parent: parent.to_string(),
                depth: child_depth,
            },
        );

        Ok(SpawnSubagentResult {
            parent: parent.to_string(),
            child: child_name,
            depth: child_depth,
            working_dir: working_dir.to_string_lossy().into_owned(),
            tool: match tool {
                AgentToolConfig::ClaudeCode { .. } => "ClaudeCode".to_string(),
                AgentToolConfig::Codex { .. } => "Codex".to_string(),
                AgentToolConfig::OpenClaw { .. } => "OpenClaw".to_string(),
                AgentToolConfig::Custom { .. } => "Custom".to_string(),
            },
        })
    }

    pub(crate) fn latest_cached_frame(
        &self,
        name: &str,
        region: &Option<ToolkitCaptureRegion>,
    ) -> Option<CachedFrame> {
        let stream = self.capture_streams.get(name)?;
        if stream.region != *region {
            return None;
        }
        let ring = stream.frames.lock();
        ring.latest().cloned()
    }

    pub(crate) fn latest_cached_frame_any(&self, name: &str) -> Option<CachedFrame> {
        let stream = self.capture_streams.get(name)?;
        let ring = stream.frames.lock();
        ring.latest().cloned()
    }

    pub(crate) fn spawn_capture_stream(
        &mut self,
        name: &str,
        session: &CaptureSessionStarted,
        region: Option<ToolkitCaptureRegion>,
    ) -> Result<(), String> {
        self.stop_capture_stream(name);

        let stop = Arc::new(AtomicBool::new(false));
        let frames = Arc::new(Mutex::new(FrameRing::new(FRAME_RING_CAPACITY)));
        let stop_clone = Arc::clone(&stop);
        let frames_clone = Arc::clone(&frames);
        let target_fps = session.target_fps;
        let region_clone = region.clone();
        let toolkit_config = self.config.toolkit.clone();

        let handle = std::thread::Builder::new()
            .name(format!("capture-{name}"))
            .spawn(move || {
                let mut runtime = match ToolkitRuntime::new(&toolkit_config) {
                    Ok(rt) => rt,
                    Err(e) => {
                        tracing::warn!(error = %e, "capture stream runtime unavailable");
                        return;
                    }
                };

                let fps = if target_fps == 0 {
                    CAPTURE_DEFAULT_FPS
                } else {
                    target_fps
                };
                let interval_ms = 1000u64.saturating_div(fps as u64).max(1);
                let interval = Duration::from_millis(interval_ms);

                while !stop_clone.load(Ordering::Relaxed) {
                    let started = Instant::now();
                    let action = ToolAction::ScreenCapture {
                        region: region_clone.clone(),
                        target_fps: fps,
                    };

                    match runtime.execute(&action) {
                        Ok(output) => {
                            if let (Some(frame), Some(frame_id)) =
                                (output.frame, output.execution.result.frame_id)
                            {
                                frames_clone.lock().push(CachedFrame {
                                    payload: frame,
                                    frame_id,
                                    captured_at: Instant::now(),
                                });
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "capture stream failed");
                        }
                    }

                    let elapsed = started.elapsed();
                    if elapsed < interval {
                        std::thread::sleep(interval - elapsed);
                    }
                }
            })
            .map_err(|e| format!("failed to spawn capture stream: {e}"))?;

        self.capture_streams.insert(
            name.to_string(),
            CaptureStream {
                session_id: session.session_id.clone(),
                target_fps: session.target_fps,
                region,
                stop,
                frames,
                handle,
            },
        );

        Ok(())
    }

    pub(crate) fn precheck_tool_action(&self, action: &ToolAction) -> Result<(), String> {
        let toolkit = &self.config.toolkit;
        match action {
            ToolAction::ScreenCapture { target_fps, .. } => {
                if !toolkit.capture.enabled {
                    return Err("capture actions are disabled by daemon toolkit config".to_string());
                }
                if *target_fps < toolkit.capture.min_fps || *target_fps > toolkit.capture.max_fps {
                    return Err(format!(
                        "capture fps {} outside allowed range {}..={}",
                        target_fps, toolkit.capture.min_fps, toolkit.capture.max_fps
                    ));
                }
            }
            ToolAction::WindowFocus { .. }
            | ToolAction::MouseMove { .. }
            | ToolAction::MouseClick { .. }
            | ToolAction::MouseDrag { .. }
            | ToolAction::KeyPress { .. }
            | ToolAction::TypeText { .. }
            | ToolAction::InputBatch { .. } => {
                if !toolkit.input.enabled {
                    return Err("input actions are disabled by daemon toolkit config".to_string());
                }
            }
            ToolAction::BrowserNavigate { .. }
            | ToolAction::BrowserEvaluate { .. }
            | ToolAction::BrowserClick { .. }
            | ToolAction::BrowserType { .. }
            | ToolAction::BrowserSnapshot { .. }
            | ToolAction::BrowserProfileStart { .. }
            | ToolAction::BrowserProfileStop { .. } => {
                if !toolkit.browser.enabled {
                    return Err("browser actions are disabled by daemon toolkit config".to_string());
                }
                if !toolkit.browser.backend.trim().eq_ignore_ascii_case("cdp") {
                    return Err(format!(
                        "unsupported browser backend '{}' (expected 'cdp')",
                        toolkit.browser.backend
                    ));
                }
            }
            ToolAction::TuiSnapshot { .. } | ToolAction::TuiInput { .. } => {}
            ToolAction::ImageAnalyze { .. } => {}
            ToolAction::TextToSpeech { .. }
            | ToolAction::CanvasRender { .. }
            | ToolAction::DeviceControl { .. } => {}
        }
        if let ToolAction::InputBatch { actions } = action {
            if actions.len() > toolkit.input.max_batch_actions as usize {
                return Err(format!(
                    "input batch has {} actions (max {})",
                    actions.len(),
                    toolkit.input.max_batch_actions
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn evaluate_runtime_tool_action(
        &self,
        principal: &str,
        action: &ToolAction,
    ) -> (Action, String, String) {
        let mapping = map_tool_action(action);
        let cedar_action = Action::new(
            principal.to_string(),
            ActionKind::ToolCall {
                tool: mapping.cedar_action.to_string(),
                args: serde_json::json!({
                    "risk_tag": mapping.risk_tag,
                    "action": action
                }),
            },
        );

        let (decision, reason) = match &self.policy_engine {
            Some(engine) => {
                let verdict = engine.evaluate(&cedar_action);
                match verdict.decision {
                    Decision::Allow => ("allow".to_string(), verdict.reason),
                    Decision::Deny => ("deny".to_string(), verdict.reason),
                }
            }
            None => (
                "deny".to_string(),
                "policy engine unavailable; denied by fail-closed runtime policy".to_string(),
            ),
        };

        (cedar_action, decision, reason)
    }

    pub(crate) fn append_runtime_audit(&self, action: Action, provenance: RuntimeAuditProvenance) {
        let audit_action = Action {
            kind: ActionKind::ToolCall {
                tool: "RuntimeComputerUse".to_string(),
                args: serde_json::to_value(&provenance)
                    .unwrap_or_else(|_| serde_json::json!({ "serialization_error": true })),
            },
            ..action
        };
        let verdict = if provenance.decision == "allow" {
            Verdict::allow(audit_action.id, provenance.reason.clone(), None)
        } else {
            Verdict::deny(audit_action.id, provenance.reason.clone(), None)
        };

        match self.open_audit_store() {
            Ok(mut store) => {
                if let Err(e) = store.append(&audit_action, &verdict) {
                    warn!(?e, "failed to append runtime audit entry");
                }
            }
            Err(e) => {
                warn!(?e, "failed to open audit ledger for runtime entry");
            }
        }
    }

    pub(crate) fn runtime_provenance(
        &self,
        agent: &str,
        operation: RuntimeOperation,
        tool_action: &ToolAction,
        decision: &str,
        reason: &str,
        outcome: &aegis_control::daemon::ToolActionExecution,
    ) -> RuntimeAuditProvenance {
        RuntimeAuditProvenance {
            agent: agent.to_string(),
            operation,
            tool_action: tool_action.clone(),
            cedar_action: tool_action.policy_action_name().to_string(),
            risk_tag: outcome.risk_tag,
            decision: decision.to_string(),
            reason: reason.to_string(),
            outcome: outcome.clone(),
        }
    }
}
