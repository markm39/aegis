//! Aegis daemon: persistent multi-agent lifecycle management.
//!
//! The daemon runs as a single persistent process managing a "fleet" of
//! supervised AI agent processes. Each agent runs in its own thread with
//! its own PTY, policy engine, adapter, and audit session.
//!
//! # Architecture
//!
//! - [`fleet::Fleet`]: owns all agent slots, handles spawning/stopping
//! - [`slot::AgentSlot`]: runtime state for one agent
//! - [`lifecycle`]: per-agent thread body (PTY + supervisor + audit)
//! - [`control`]: Unix socket server for external control
//! - [`persistence`]: launchd integration, PID files, caffeinate
//! - [`state`]: crash recovery via persistent state.json

pub mod control;
pub mod cron;
pub mod dashboard;
pub mod fleet;
pub mod lifecycle;
pub mod memory;
pub mod ndjson_fmt;
pub mod persistence;
pub mod plugins;
pub mod prompt_builder;
pub mod slot;
pub mod state;
pub mod stream_fmt;
pub mod session_tools;
pub mod tool_contract;
pub mod toolkit_runtime;
pub mod web_tools;

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use tracing::{info, warn};

use aegis_channel::ChannelInput;
use aegis_control::alias::AliasRegistry;
use aegis_control::daemon::{
    AgentDetail, AgentSummary, BrowserToolData, CaptureSessionStarted, DaemonCommand, DaemonPing,
    DaemonResponse, DashboardAgent, DashboardPendingPrompt, DashboardSnapshot, DashboardStatus,
    FramePayload, OrchestratorAgentView, OrchestratorSnapshot, ParityDiffReport,
    ParityFeatureStatus, ParityStatusReport, ParityVerifyReport, ParityViolation,
    PendingPromptSummary, RuntimeAuditProvenance, RuntimeCapabilities, RuntimeOperation,
    SessionHistory, SessionInfo, SpawnSubagentRequest, SpawnSubagentResult, ToolActionExecution,
    ToolActionOutcome, ToolBatchOutcome, ToolUseVerdict, TuiToolData,
};
use aegis_control::event::{EventStats, PilotEventKind, PilotWebhookEvent};
use aegis_control::hooks;
use aegis_ledger::AuditStore;
use aegis_toolkit::contract::{CaptureRegion as ToolkitCaptureRegion, RiskTag, ToolAction};
use aegis_toolkit::policy::map_tool_action;
use aegis_types::daemon::{
    AgentSlotConfig, AgentStatus, AgentToolConfig, DaemonConfig, RestartPolicy,
};
use aegis_types::AegisConfig;
use aegis_types::{Action, ActionKind, Decision, Verdict};

use crate::control::DaemonCmdRx;
use crate::fleet::Fleet;
use crate::slot::NotableEvent;
use crate::state::DaemonState;
use crate::tool_contract::render_orchestrator_tool_contract;
use crate::toolkit_runtime::{ToolkitOutput, ToolkitRuntime, TuiRuntimeBridge};

const FRAME_RING_CAPACITY: usize = 5;
const CAPTURE_DEFAULT_FPS: u16 = 30;
const BROWSER_SESSION_TTL: Duration = Duration::from_secs(300);
const DEFAULT_SUBAGENT_DEPTH_LIMIT: u8 = 3;

#[derive(Debug, Clone)]
struct SubagentSession {
    parent: String,
    depth: u8,
}

#[derive(Debug, Clone)]
struct CachedFrame {
    payload: FramePayload,
    frame_id: u64,
    captured_at: Instant,
}

struct FleetTuiBridge<'a> {
    fleet: &'a Fleet,
    default_target: &'a str,
}

impl TuiRuntimeBridge for FleetTuiBridge<'_> {
    fn snapshot(&self, session_id: &str) -> Result<TuiToolData, String> {
        let target = if session_id.is_empty() {
            self.default_target
        } else {
            session_id
        };
        let lines = self.fleet.agent_output(target, 200)?;
        Ok(TuiToolData::Snapshot {
            target: target.to_string(),
            text: lines.join("\n"),
            cursor: [0, 0],
            size: [0, 0],
        })
    }

    fn send_input(&self, session_id: &str, text: &str) -> Result<TuiToolData, String> {
        let target = if session_id.is_empty() {
            self.default_target
        } else {
            session_id
        };
        self.fleet.send_to_agent(target, text)?;
        Ok(TuiToolData::Input {
            target: target.to_string(),
            sent: true,
        })
    }
}

struct FrameRing {
    frames: VecDeque<CachedFrame>,
    capacity: usize,
}

impl FrameRing {
    fn new(capacity: usize) -> Self {
        Self {
            frames: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    fn push(&mut self, frame: CachedFrame) {
        if self.frames.len() >= self.capacity {
            self.frames.pop_front();
        }
        self.frames.push_back(frame);
    }

    fn latest(&self) -> Option<&CachedFrame> {
        self.frames.back()
    }
}

#[allow(dead_code)]
struct CaptureStream {
    session_id: String,
    target_fps: u16,
    region: Option<ToolkitCaptureRegion>,
    stop: Arc<AtomicBool>,
    frames: Arc<Mutex<FrameRing>>,
    handle: std::thread::JoinHandle<()>,
}

/// Whether hook policy checks should fail open on control/policy failures.
///
/// Defaults to fail-closed. Set `AEGIS_HOOK_FAIL_OPEN=1` (or true/yes/on)
/// only for lower-trust development environments.
fn hook_fail_open_enabled() -> bool {
    std::env::var("AEGIS_HOOK_FAIL_OPEN")
        .ok()
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            matches!(v.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

fn status_label(status: &AgentStatus) -> String {
    match status {
        AgentStatus::Pending => "pending".to_string(),
        AgentStatus::Running { pid } => format!("running (pid {pid})"),
        AgentStatus::Stopped { exit_code } => format!("stopped (exit {exit_code})"),
        AgentStatus::Crashed {
            exit_code,
            restart_in_secs,
        } => format!("crashed (exit {exit_code}, restart in {restart_in_secs}s)"),
        AgentStatus::Failed {
            exit_code,
            restart_count,
        } => format!("failed (exit {exit_code}, restarts {restart_count})"),
        AgentStatus::Stopping => "stopping".to_string(),
        AgentStatus::Disabled => "disabled".to_string(),
    }
}

/// Compute runtime capability and policy-mediation coverage for an agent slot.
fn runtime_capabilities(config: &AgentSlotConfig) -> RuntimeCapabilities {
    use aegis_types::daemon::AgentToolConfig;

    let (tool, headless, policy_mediation, mediation_note, mediation_mode, hook_bridge, tool_coverage, compliance_mode) =
        match &config.tool {
        AgentToolConfig::ClaudeCode { .. } => (
            "ClaudeCode".to_string(),
            true,
            "enforced".to_string(),
            "Cedar policy checks are enforced via PreToolUse hooks".to_string(),
            "enforced".to_string(),
            "connected".to_string(),
            "covered".to_string(),
            "blocking".to_string(),
        ),
        AgentToolConfig::Codex { .. } => (
            "Codex".to_string(),
            true,
            "partial".to_string(),
            "runtime mediation is limited until a secure bridge is available".to_string(),
            "partial".to_string(),
            "unavailable".to_string(),
            "partial".to_string(),
            "advisory".to_string(),
        ),
        AgentToolConfig::OpenClaw { .. } => {
            let bridge_connected = hooks::openclaw_bridge_connected(&config.working_dir);
            if bridge_connected {
                (
                    "OpenClaw".to_string(),
                    true,
                    "enforced".to_string(),
                    "secure runtime bridge connected; privileged actions are policy-gated"
                        .to_string(),
                    "enforced".to_string(),
                    "connected".to_string(),
                    "covered".to_string(),
                    "blocking".to_string(),
                )
            } else {
                (
                    "OpenClaw".to_string(),
                    true,
                    "enforced".to_string(),
                    "secure runtime bridge disconnected; privileged actions are fail-closed"
                        .to_string(),
                    "enforced".to_string(),
                    "disconnected".to_string(),
                    "restricted".to_string(),
                    "blocking".to_string(),
                )
            }
        }
        AgentToolConfig::Custom { .. } => (
            "Custom".to_string(),
            true,
            "custom".to_string(),
            "Custom runtime; policy mediation depends on external integration".to_string(),
            "custom".to_string(),
            "custom".to_string(),
            "custom".to_string(),
            "custom".to_string(),
        ),
    };
    let (auth_mode, auth_ready, auth_hint) = tool_auth_readiness(config);

    RuntimeCapabilities {
        name: config.name.clone(),
        tool,
        headless,
        policy_mediation,
        mediation_note,
        mediation_mode,
        hook_bridge,
        tool_coverage,
        compliance_mode,
        active_capture_session_id: None,
        active_capture_target_fps: None,
        last_tool_action: None,
        last_tool_risk_tag: None,
        last_tool_decision: None,
        last_tool_note: None,
        toolkit_capture_enabled: true,
        toolkit_input_enabled: true,
        toolkit_browser_enabled: true,
        toolkit_browser_backend: "cdp".to_string(),
        loop_max_micro_actions: 8,
        loop_time_budget_ms: 1200,
        auth_mode,
        auth_ready,
        auth_hint,
        tool_contract: String::new(),
    }
}

fn env_present(var: &str) -> bool {
    std::env::var(var)
        .ok()
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
}

fn tool_auth_readiness(config: &AgentSlotConfig) -> (String, bool, String) {
    use aegis_types::daemon::AgentToolConfig;

    match &config.tool {
        AgentToolConfig::ClaudeCode { .. } => {
            let oauth = env_present("CLAUDE_CODE_OAUTH_TOKEN");
            let api_key = env_present("ANTHROPIC_API_KEY") || env_present("CLAUDE_API_KEY");
            if oauth {
                (
                    "oauth".to_string(),
                    true,
                    "Claude OAuth token detected in daemon environment".to_string(),
                )
            } else if api_key {
                (
                    "api-key".to_string(),
                    true,
                    "Anthropic API key detected in daemon environment".to_string(),
                )
            } else {
                (
                    "oauth|api-key".to_string(),
                    false,
                    "No Claude auth detected. Configure with `aegis auth add anthropic --method oauth` or provide ANTHROPIC_API_KEY.".to_string(),
                )
            }
        }
        AgentToolConfig::Codex { .. } => {
            let oauth = env_present("OPENAI_ACCESS_TOKEN");
            let api_key = env_present("OPENAI_API_KEY");
            if oauth {
                (
                    "oauth".to_string(),
                    true,
                    "OpenAI OAuth token detected in daemon environment".to_string(),
                )
            } else if api_key {
                (
                    "api-key".to_string(),
                    true,
                    "OpenAI API key detected in daemon environment".to_string(),
                )
            } else {
                (
                    "oauth|api-key".to_string(),
                    false,
                    "No OpenAI auth detected. Configure with `aegis auth add openai --method oauth` or provide OPENAI_API_KEY.".to_string(),
                )
            }
        }
        AgentToolConfig::OpenClaw { .. } => {
            let token = env_present("OPENCLAW_GATEWAY_TOKEN")
                || env_present("OPENCLAW_AUTH_TOKEN")
                || env_present("OPENCLAW_API_KEY");
            if token {
                (
                    "token".to_string(),
                    true,
                    "OpenClaw auth token detected in daemon environment".to_string(),
                )
            } else {
                (
                    "token".to_string(),
                    false,
                    "No OpenClaw token detected. Configure gateway token or OPENCLAW_GATEWAY_TOKEN.".to_string(),
                )
            }
        }
        AgentToolConfig::Custom { .. } => (
            "custom".to_string(),
            false,
            "Custom runtime auth must be configured by the command/tool itself".to_string(),
        ),
    }
}

fn session_key_for_agent(name: &str) -> String {
    format!("agent:{name}:main")
}

fn parse_session_key(session_key: &str) -> Option<String> {
    let trimmed = session_key.trim();
    let parts: Vec<&str> = trimmed.split(':').collect();
    if parts.len() == 3 && parts[0] == "agent" && parts[2] == "main" {
        let name = parts[1].to_string();
        if name.is_empty() {
            None
        } else {
            Some(name)
        }
    } else {
        None
    }
}

#[derive(Debug, Clone, Default)]
struct ParityFeatureRow {
    feature_id: String,
    status: String,
    risk_level: String,
    owner: String,
    required_controls: Vec<String>,
    acceptance_tests: Vec<String>,
    evidence_paths: Vec<String>,
}

fn parity_dir() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("AEGIS_PARITY_DIR") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return std::path::PathBuf::from(trimmed);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        return std::path::PathBuf::from(home).join("aegis-parity");
    }
    std::path::PathBuf::from("aegis-parity")
}

fn strip_yaml_scalar(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FeatureListField {
    RequiredControls,
    AcceptanceTests,
    EvidencePaths,
}

fn parse_features_yaml(raw: &str) -> (String, Vec<ParityFeatureRow>) {
    let mut updated_at_utc = String::new();
    let mut rows: Vec<ParityFeatureRow> = Vec::new();
    let mut current: Option<ParityFeatureRow> = None;
    let mut active_list_field: Option<FeatureListField> = None;

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some((k, v)) = trimmed.split_once(':') {
            if k.trim() == "updated_at_utc" {
                updated_at_utc = strip_yaml_scalar(v);
            }
        }

        if let Some(value) = trimmed.strip_prefix("- feature_id:") {
            if let Some(prev) = current.take() {
                if !prev.feature_id.is_empty() {
                    rows.push(prev);
                }
            }
            current = Some(ParityFeatureRow {
                feature_id: strip_yaml_scalar(value),
                ..ParityFeatureRow::default()
            });
            active_list_field = None;
            continue;
        }

        let Some(row) = current.as_mut() else {
            continue;
        };

        if let Some(value) = trimmed.strip_prefix("aegis_status:") {
            row.status = strip_yaml_scalar(value);
            active_list_field = None;
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("risk_level:") {
            row.risk_level = strip_yaml_scalar(value);
            active_list_field = None;
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("owner:") {
            row.owner = strip_yaml_scalar(value);
            active_list_field = None;
            continue;
        }
        if trimmed.starts_with("required_controls:") {
            active_list_field = Some(FeatureListField::RequiredControls);
            continue;
        }
        if trimmed.starts_with("acceptance_tests:") {
            active_list_field = Some(FeatureListField::AcceptanceTests);
            continue;
        }
        if trimmed.starts_with("evidence_paths:") {
            active_list_field = Some(FeatureListField::EvidencePaths);
            continue;
        }
        if let Some(field) = active_list_field {
            if let Some(value) = trimmed.strip_prefix("- ") {
                let item = strip_yaml_scalar(value);
                if !item.is_empty() {
                    match field {
                        FeatureListField::RequiredControls => row.required_controls.push(item),
                        FeatureListField::AcceptanceTests => row.acceptance_tests.push(item),
                        FeatureListField::EvidencePaths => row.evidence_paths.push(item),
                    }
                }
                continue;
            }
            if trimmed.contains(':') {
                active_list_field = None;
            }
        }
    }

    if let Some(prev) = current.take() {
        if !prev.feature_id.is_empty() {
            rows.push(prev);
        }
    }

    (updated_at_utc, rows)
}

fn parse_security_controls_yaml(raw: &str) -> HashSet<String> {
    let mut controls = HashSet::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("- control_id:") {
            let control_id = strip_yaml_scalar(value);
            if !control_id.is_empty() {
                controls.insert(control_id);
            }
        }
    }
    controls
}

fn parity_status_is_valid(status: &str) -> bool {
    matches!(status, "complete" | "partial" | "missing" | "blocked")
}

fn parity_risk_level_is_valid(risk_level: &str) -> bool {
    matches!(risk_level, "low" | "medium" | "high" | "critical")
}

fn parity_status_report_from_dir(dir: &std::path::Path) -> Result<ParityStatusReport, String> {
    let features_path = dir.join("matrix").join("features.yaml");
    let controls_path = dir.join("matrix").join("security_controls.yaml");

    let features_raw = std::fs::read_to_string(&features_path)
        .map_err(|e| format!("failed to read {}: {e}", features_path.display()))?;
    let controls_raw = std::fs::read_to_string(&controls_path)
        .map_err(|e| format!("failed to read {}: {e}", controls_path.display()))?;

    let (updated_at_utc, rows) = parse_features_yaml(&features_raw);
    let known_controls = parse_security_controls_yaml(&controls_raw);

    let mut complete_features = 0usize;
    let mut partial_features = 0usize;
    let mut high_risk_blockers = 0usize;
    let mut features: Vec<ParityFeatureStatus> = Vec::with_capacity(rows.len());

    for row in rows {
        let status = if row.status.trim().is_empty() {
            "unknown".to_string()
        } else {
            row.status.clone()
        };
        if status == "complete" {
            complete_features += 1;
        } else if status == "partial" {
            partial_features += 1;
        }
        let missing_controls: Vec<String> = row
            .required_controls
            .iter()
            .filter(|c| !known_controls.contains(*c))
            .cloned()
            .collect();

        let is_high_risk = row.risk_level.eq_ignore_ascii_case("high")
            || row.risk_level.eq_ignore_ascii_case("critical");
        if is_high_risk && (status != "complete" || !missing_controls.is_empty()) {
            high_risk_blockers += 1;
        }

        features.push(ParityFeatureStatus {
            feature_id: row.feature_id,
            status,
            risk_level: row.risk_level,
            owner: row.owner,
            required_controls: row.required_controls,
            missing_controls,
        });
    }

    Ok(ParityStatusReport {
        source_dir: dir.display().to_string(),
        updated_at_utc,
        total_features: features.len(),
        complete_features,
        partial_features,
        high_risk_blockers,
        features,
    })
}

fn parity_status_report() -> Result<ParityStatusReport, String> {
    let dir = parity_dir();
    parity_status_report_from_dir(&dir)
}

fn parity_diff_report_from_dir(dir: &std::path::Path) -> Result<ParityDiffReport, String> {
    let reports_dir = dir.join("reports");
    let mut latest_path: Option<std::path::PathBuf> = None;
    let mut latest_mtime: Option<std::time::SystemTime> = None;

    let entries = std::fs::read_dir(&reports_dir)
        .map_err(|e| format!("failed to read {}: {e}", reports_dir.display()))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let mtime = match entry.metadata().and_then(|m| m.modified()) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if latest_mtime.is_none_or(|current| mtime > current) {
            latest_mtime = Some(mtime);
            latest_path = Some(path);
        }
    }

    let report_path = latest_path
        .ok_or_else(|| format!("no parity reports found in {}", reports_dir.display()))?;
    let raw = std::fs::read_to_string(&report_path)
        .map_err(|e| format!("failed to read {}: {e}", report_path.display()))?;

    let mut upstream_sha = String::new();
    let mut changed_files = 0usize;
    let mut in_changed_files = false;
    for line in raw.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("- new_processed_sha:") {
            upstream_sha = strip_yaml_scalar(value);
        }
        if trimmed == "## Changed Files" {
            in_changed_files = true;
            continue;
        }
        if in_changed_files && trimmed.starts_with("## ") {
            in_changed_files = false;
        }
        if in_changed_files && trimmed.starts_with("- ") {
            changed_files += 1;
        }
    }

    let status = parity_status_report_from_dir(dir)?;
    let impacted_feature_ids = status
        .features
        .into_iter()
        .filter(|f| {
            (f.risk_level.eq_ignore_ascii_case("high")
                || f.risk_level.eq_ignore_ascii_case("critical"))
                && (f.status != "complete")
        })
        .map(|f| f.feature_id)
        .collect::<Vec<_>>();

    Ok(ParityDiffReport {
        report_file: report_path.to_string_lossy().into_owned(),
        upstream_sha,
        changed_files,
        impacted_feature_ids,
    })
}

fn parity_diff_report() -> Result<ParityDiffReport, String> {
    let dir = parity_dir();
    parity_diff_report_from_dir(&dir)
}

fn parity_verify_report_from_dir(dir: &std::path::Path) -> Result<ParityVerifyReport, String> {
    let features_path = dir.join("matrix").join("features.yaml");
    let controls_path = dir.join("matrix").join("security_controls.yaml");

    let features_raw = std::fs::read_to_string(&features_path)
        .map_err(|e| format!("failed to read {}: {e}", features_path.display()))?;
    let controls_raw = std::fs::read_to_string(&controls_path)
        .map_err(|e| format!("failed to read {}: {e}", controls_path.display()))?;

    let (_, rows) = parse_features_yaml(&features_raw);
    let known_controls = parse_security_controls_yaml(&controls_raw);

    let mut violations = Vec::new();
    let mut violations_struct: Vec<ParityViolation> = Vec::new();
    let mut push_violation = |rule_id: &str, feature_id: &str, message: String| {
        violations.push(format!("{rule_id}|{feature_id}|{message}"));
        violations_struct.push(ParityViolation {
            rule_id: rule_id.to_string(),
            feature_id: feature_id.to_string(),
            message,
        });
    };

    for row in &rows {
        let status = row.status.trim().to_ascii_lowercase();
        let risk_level = row.risk_level.trim().to_ascii_lowercase();

        if !parity_status_is_valid(&status) {
            push_violation(
                "R_STATUS_ENUM",
                &row.feature_id,
                format!("unsupported status '{}'", row.status),
            );
        }
        if !parity_risk_level_is_valid(&risk_level) {
            push_violation(
                "R_RISK_ENUM",
                &row.feature_id,
                format!("unsupported risk level '{}'", row.risk_level),
            );
        }

        let is_complete = status == "complete";
        let is_high_risk = matches!(risk_level.as_str(), "high" | "critical");

        if is_high_risk && !is_complete {
            push_violation(
                "R_HIGH_RISK_COMPLETE",
                &row.feature_id,
                format!(
                    "high/critical feature must be complete (status={})",
                    row.status
                ),
            );
        }

        let missing_controls: Vec<&str> = row
            .required_controls
            .iter()
            .map(String::as_str)
            .filter(|control| !known_controls.contains(*control))
            .collect();

        if is_complete && !missing_controls.is_empty() {
            push_violation(
                "R_COMPLETE_CONTROLS",
                &row.feature_id,
                format!("missing controls: {}", missing_controls.join(", ")),
            );
        }
        if is_complete && row.acceptance_tests.is_empty() {
            push_violation(
                "R_COMPLETE_TESTS",
                &row.feature_id,
                "complete feature requires acceptance_tests".to_string(),
            );
        }
        if is_complete && row.evidence_paths.is_empty() {
            push_violation(
                "R_COMPLETE_EVIDENCE",
                &row.feature_id,
                "complete feature requires evidence_paths".to_string(),
            );
        }
    }

    Ok(ParityVerifyReport {
        ok: violations.is_empty(),
        checked_features: rows.len(),
        violations,
        violations_struct,
    })
}

fn parity_verify_report() -> Result<ParityVerifyReport, String> {
    let dir = parity_dir();
    parity_verify_report_from_dir(&dir)
}

/// The daemon runtime: main loop managing the fleet and control plane.
pub struct DaemonRuntime {
    /// Fleet of managed agents.
    pub fleet: Fleet,
    /// Daemon configuration.
    pub config: DaemonConfig,
    /// Shutdown signal.
    pub shutdown: Arc<AtomicBool>,
    /// When the daemon started.
    pub started_at: Instant,
    /// Sender for outbound events to the notification channel (Telegram).
    channel_tx: Option<mpsc::Sender<ChannelInput>>,
    /// Receiver for inbound commands from the notification channel.
    channel_cmd_rx: Option<mpsc::Receiver<DaemonCommand>>,
    /// Thread handle for the notification channel (detect panics).
    channel_thread: Option<std::thread::JoinHandle<()>>,
    /// Cedar policy engine for evaluating tool use requests from hooks.
    policy_engine: Option<aegis_policy::PolicyEngine>,
    /// Aegis config (needed for policy reload).
    aegis_config: AegisConfig,
    /// Active capture sessions keyed by agent name.
    capture_sessions: HashMap<String, CaptureSessionStarted>,
    /// Active capture streams keyed by agent name.
    capture_streams: HashMap<String, CaptureStream>,
    /// Last tool-action execution metadata keyed by agent name.
    last_tool_actions: std::collections::HashMap<String, ToolActionExecution>,
    /// Optional computer-use runtime for orchestrator actions.
    toolkit_runtime: Option<ToolkitRuntime>,
    /// Runtime-only subagent sessions keyed by child agent name.
    subagents: HashMap<String, SubagentSession>,
    /// Dashboard listen address (if enabled).
    dashboard_listen: Option<String>,
    /// Dashboard access token (if enabled).
    dashboard_token: Option<String>,
    /// Last heartbeat sent per orchestrator agent.
    heartbeat_last_sent: HashMap<String, Instant>,
    /// Command alias registry.
    alias_registry: AliasRegistry,
}

impl DaemonRuntime {
    /// Create a new daemon runtime from configuration.
    pub fn new(config: DaemonConfig, aegis_config: AegisConfig) -> Self {
        let fleet = Fleet::new(&config, aegis_config.clone());

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

        Self {
            fleet,
            config,
            shutdown: Arc::new(AtomicBool::new(false)),
            started_at: Instant::now(),
            channel_tx: None,
            channel_cmd_rx: None,
            channel_thread: None,
            policy_engine,
            aegis_config,
            capture_sessions: HashMap::new(),
            capture_streams: HashMap::new(),
            last_tool_actions: HashMap::new(),
            toolkit_runtime: None,
            subagents: HashMap::new(),
            dashboard_listen: None,
            dashboard_token: None,
            heartbeat_last_sent: HashMap::new(),
            alias_registry,
        }
    }

    fn stop_capture_stream(&mut self, name: &str) {
        if let Some(stream) = self.capture_streams.remove(name) {
            stream.stop.store(true, Ordering::Relaxed);
            let _ = stream.handle.join();
        }
    }

    fn stop_all_capture_streams(&mut self) {
        let names: Vec<String> = self.capture_streams.keys().cloned().collect();
        for name in names {
            self.stop_capture_stream(&name);
        }
    }

    fn subagent_depth(&self, name: &str) -> u8 {
        self.subagents.get(name).map(|s| s.depth).unwrap_or(0)
    }

    fn generated_subagent_name(parent: &str) -> String {
        let id = uuid::Uuid::new_v4().simple().to_string();
        format!("{parent}-sub-{}", &id[..8])
    }

    fn restrict_subagent_tool(tool: &AgentToolConfig) -> Result<AgentToolConfig, String> {
        match tool {
            AgentToolConfig::ClaudeCode { .. } => Ok(AgentToolConfig::ClaudeCode {
                skip_permissions: false,
                one_shot: false,
                extra_args: Vec::new(),
            }),
            AgentToolConfig::Codex { .. } => Ok(AgentToolConfig::Codex {
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

    fn append_audit_entry(&self, action: &Action, verdict: &Verdict) {
        match AuditStore::open(&self.aegis_config.ledger_path) {
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

    fn authorize_subagent_spawn(
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

    fn collect_subagent_descendants(&self, root: &str) -> Vec<String> {
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

    fn cleanup_agent_runtime_state(&mut self, name: &str) {
        self.stop_capture_stream(name);
        self.capture_sessions.remove(name);
        self.last_tool_actions.remove(name);
    }

    fn remove_subagent_descendants(&mut self, root: &str) {
        let descendants = self.collect_subagent_descendants(root);
        for child in descendants.into_iter().rev() {
            self.cleanup_agent_runtime_state(&child);
            self.fleet.remove_agent(&child);
            self.subagents.remove(&child);
        }
    }

    fn spawn_subagent(
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
            name: child_name.clone(),
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
        };

        self.fleet.add_agent(child_config);
        if request.start {
            self.fleet.start_agent(&child_name);
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

    fn latest_cached_frame(
        &self,
        name: &str,
        region: &Option<ToolkitCaptureRegion>,
    ) -> Option<CachedFrame> {
        let stream = self.capture_streams.get(name)?;
        if stream.region != *region {
            return None;
        }
        let ring = stream.frames.lock().ok()?;
        ring.latest().cloned()
    }

    fn latest_cached_frame_any(&self, name: &str) -> Option<CachedFrame> {
        let stream = self.capture_streams.get(name)?;
        let ring = stream.frames.lock().ok()?;
        ring.latest().cloned()
    }

    fn spawn_capture_stream(
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
                                if let Ok(mut ring) = frames_clone.lock() {
                                    ring.push(CachedFrame {
                                        payload: frame,
                                        frame_id,
                                        captured_at: Instant::now(),
                                    });
                                }
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

    fn precheck_tool_action(&self, action: &ToolAction) -> Result<(), String> {
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

    fn evaluate_runtime_tool_action(
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

    fn append_runtime_audit(&self, action: Action, provenance: RuntimeAuditProvenance) {
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

        match AuditStore::open(&self.aegis_config.ledger_path) {
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

    fn runtime_provenance(
        &self,
        agent: &str,
        operation: RuntimeOperation,
        tool_action: &ToolAction,
        decision: &str,
        reason: &str,
        outcome: &ToolActionExecution,
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

    /// Run the daemon main loop. Blocks until shutdown is signaled.
    ///
    /// 1. Write PID file
    /// 2. Recover from previous crash (if applicable)
    /// 3. Start control socket server
    /// 4. Start all enabled agents
    /// 5. Enter tick loop (health checks, restart logic, command dispatch)
    /// 6. On shutdown: stop all agents, clean up
    pub fn run(&mut self) -> Result<(), String> {
        // Write PID file
        let _pid_path = persistence::write_pid_file()?;

        // Check for previous state and recover (close orphaned audit sessions)
        if let Some(prev_state) = DaemonState::load() {
            state::recover_from_crash(&prev_state, &self.aegis_config.ledger_path);
            // Restore restart counts from previous daemon instance so
            // max_restarts guards carry across daemon restarts.
            for agent_state in &prev_state.agents {
                self.fleet
                    .restore_restart_count(&agent_state.name, agent_state.restart_count);
            }
        }

        // Optionally start caffeinate (keep handle alive until function returns;
        // caffeinate self-terminates via -w when daemon PID exits)
        let _caffeinate_child = if self.config.persistence.prevent_sleep {
            Some(persistence::start_caffeinate()?)
        } else {
            None
        };

        // Start control socket server
        let (cmd_tx, mut cmd_rx) = control::spawn_control_server(
            self.config.control.socket_path.clone(),
            Arc::clone(&self.shutdown),
        )?;

        // Start dashboard server (read-only web UI)
        if self.config.dashboard.enabled && !self.config.dashboard.listen.trim().is_empty() {
            let token = if self.config.dashboard.api_key.trim().is_empty() {
                uuid::Uuid::new_v4().to_string()
            } else {
                self.config.dashboard.api_key.clone()
            };
            let listen = self.config.dashboard.listen.clone();
            if let Err(e) = dashboard::spawn_dashboard_server(
                listen.clone(),
                token.clone(),
                cmd_tx.clone(),
                Arc::clone(&self.shutdown),
                self.config.dashboard.rate_limit_burst,
                self.config.dashboard.rate_limit_per_sec,
            ) {
                warn!(error = %e, "failed to start dashboard server");
            } else {
                let url = format!("http://{listen}/?token={token}");
                info!(%url, "dashboard server started");
                self.dashboard_listen = Some(listen);
                self.dashboard_token = Some(token);
            }
        }

        // Start notification channel (Telegram) if configured
        if let Some(ref channel_config) = self.config.channel {
            let (input_tx, input_rx) = mpsc::channel();
            let (feedback_tx, feedback_rx) = mpsc::channel();
            let config = channel_config.clone();

            match std::thread::Builder::new()
                .name("channel".to_string())
                .spawn(move || {
                    aegis_channel::run_fleet(config, input_rx, Some(feedback_tx));
                }) {
                Ok(handle) => {
                    self.channel_tx = Some(input_tx);
                    self.channel_cmd_rx = Some(feedback_rx);
                    self.channel_thread = Some(handle);
                    info!("notification channel started");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to spawn notification channel thread");
                }
            }
        }

        info!(
            agents = self.fleet.agent_count(),
            socket = %self.config.control.socket_path.display(),
            "daemon starting"
        );

        // Start all enabled agents
        self.fleet.start_all();

        // Main loop
        //
        // Uses recv_timeout instead of sleep so the daemon wakes immediately
        // when a command arrives from the fleet TUI or other clients. Heavy
        // work (fleet tick, channel drain, state save) is rate-limited to ~1s.
        let tick_interval = Duration::from_secs(1);
        let state_save_interval = Duration::from_secs(30);
        let mut last_state_save = Instant::now();
        let mut last_tick = Instant::now();

        while !self.shutdown.load(Ordering::Relaxed) {
            // Block until a command arrives OR the remaining tick interval expires.
            // This makes the daemon respond to commands instantly instead of
            // sleeping for up to 1 second.
            let timeout = tick_interval.saturating_sub(last_tick.elapsed());
            match cmd_rx.recv_timeout(timeout) {
                Ok((cmd, reply_tx)) => {
                    let response = self.handle_command(cmd);
                    let _ = reply_tx.send(response);
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    warn!("control channel disconnected");
                    break;
                }
            }

            // Drain any additional commands that queued up
            self.drain_commands(&mut cmd_rx);

            // Fleet tick + heavy work only at ~1s intervals
            if last_tick.elapsed() >= tick_interval {
                // Drain inbound commands from the notification channel
                self.drain_channel_commands();

                // Check if the channel thread has exited (panic or unexpected exit)
                if let Some(handle) = &self.channel_thread {
                    if handle.is_finished() {
                        let handle = self.channel_thread.take().unwrap();
                        match handle.join() {
                            Ok(()) => {
                                tracing::warn!("notification channel thread exited unexpectedly")
                            }
                            Err(_) => tracing::error!("notification channel thread panicked"),
                        }
                        // Clear senders so we don't keep trying to send to a dead thread
                        self.channel_tx = None;
                        self.channel_cmd_rx = None;
                    }
                }

                // Tick the fleet (check for exits, apply restart policies)
                let notable_events = self.fleet.tick();

                // Relay completed subagent results back to parent orchestrators.
                self.relay_subagent_results(&notable_events);

                // Forward notable events to the notification channel
                self.forward_to_channel(notable_events);

                // Periodic orchestrator heartbeat (review cycle)
                self.maybe_send_heartbeat();

                if let Some(runtime) = self.toolkit_runtime.as_mut() {
                    runtime.prune_idle_sessions(BROWSER_SESSION_TTL);
                }

                // Periodically save state
                if last_state_save.elapsed() >= state_save_interval {
                    self.save_state();
                    last_state_save = Instant::now();
                }

                last_tick = Instant::now();
            }
        }

        info!("daemon shutting down");

        // Stop all running agents to prevent orphaned processes
        self.fleet.stop_all();
        self.stop_all_capture_streams();
        if let Some(runtime) = self.toolkit_runtime.as_mut() {
            runtime.shutdown();
        }

        // Save final state
        self.save_state();

        // Clean up
        persistence::remove_pid_file();
        DaemonState::remove();

        info!("daemon shutdown complete");
        Ok(())
    }

    /// Drain all pending commands from the control socket.
    fn drain_commands(&mut self, cmd_rx: &mut DaemonCmdRx) {
        while let Ok((cmd, reply_tx)) = cmd_rx.try_recv() {
            let response = self.handle_command(cmd);
            let _ = reply_tx.send(response);
        }
    }

    /// Drain inbound commands from the notification channel (Telegram).
    ///
    /// These commands were parsed from Telegram messages and converted to
    /// `DaemonCommand`s by the channel runner. We process them the same as
    /// control socket commands, and send the response back as a text message.
    fn drain_channel_commands(&mut self) {
        let cmds: Vec<DaemonCommand> = match &self.channel_cmd_rx {
            Some(rx) => rx.try_iter().collect(),
            None => return,
        };

        for cmd in cmds {
            info!(?cmd, "processing command from notification channel");
            let response = self.handle_command(cmd);

            // Send the response back to the user via the notification channel
            if let Some(tx) = &self.channel_tx {
                let text = if response.ok {
                    response.message
                } else {
                    format!("Error: {}", response.message)
                };
                let _ = tx.send(ChannelInput::TextMessage(text));
            }
        }
    }

    fn maybe_send_heartbeat(&mut self) {
        let Some(tx) = &self.channel_tx else {
            return;
        };
        let now = Instant::now();
        for name in self.fleet.agent_names_sorted() {
            let Some(slot) = self.fleet.slot(&name) else {
                continue;
            };
            let Some(orch) = &slot.config.orchestrator else {
                continue;
            };
            if !matches!(slot.status, AgentStatus::Running { .. }) {
                continue;
            }
            let interval = Duration::from_secs(orch.review_interval_secs.max(30));
            let due = self
                .heartbeat_last_sent
                .get(&name)
                .map(|t| t.elapsed() >= interval)
                .unwrap_or(true);
            if !due {
                continue;
            }

            let running = self.fleet.running_count();
            let total = self.fleet.agent_count();
            let pending = self.fleet.pending_total();
            let msg = format!(
                "Heartbeat: review cycle due for {name} (interval {}s). Agents: {running}/{total} running. Pending prompts: {pending}.",
                orch.review_interval_secs
            );
            let _ = tx.send(ChannelInput::TextMessage(msg));
            self.heartbeat_last_sent.insert(name.clone(), now);
        }
    }

    fn relay_subagent_results(&mut self, events: &[(String, NotableEvent)]) {
        for (child_name, event) in events {
            let NotableEvent::ChildExited { exit_code } = event else {
                continue;
            };
            let Some(meta) = self.subagents.get(child_name).cloned() else {
                continue;
            };
            let parent = meta.parent.clone();

            let (status, role, task, working_dir, output_tail) = match self.fleet.slot(child_name) {
                Some(slot) => {
                    slot.drain_output();
                    (
                        status_label(&slot.status),
                        slot.config.role.clone(),
                        slot.config.task.clone(),
                        slot.config.working_dir.to_string_lossy().into_owned(),
                        slot.get_recent_output(40),
                    )
                }
                None => ("unknown".to_string(), None, None, String::new(), Vec::new()),
            };

            let summary = serde_json::json!({
                "event": "subagent_result",
                "parent": parent.clone(),
                "child": child_name,
                "depth": meta.depth,
                "exit_code": exit_code,
                "status": status,
                "role": role,
                "task": task,
                "working_dir": working_dir,
                "output_tail": output_tail,
            });
            let message = format!("AEGIS_SUBAGENT_RESULT {}", summary);

            let policy_action = Action::new(
                parent.clone(),
                ActionKind::ToolCall {
                    tool: "SubagentResultReturn".to_string(),
                    args: serde_json::json!({
                        "parent": parent.clone(),
                        "child": child_name,
                        "depth": meta.depth,
                        "exit_code": exit_code,
                    }),
                },
            );
            let (decision, policy_reason) = match &self.policy_engine {
                Some(engine) => {
                    let verdict = engine.evaluate(&policy_action);
                    (verdict.decision, verdict.reason)
                }
                None => (
                    Decision::Deny,
                    "policy engine unavailable; denied by fail-closed subagent result policy"
                        .to_string(),
                ),
            };

            let (delivered, delivery_error) = match decision {
                Decision::Allow => match self.fleet.send_to_agent(&parent, &message) {
                    Ok(()) => (true, None),
                    Err(err) => {
                        warn!(
                            parent = %parent,
                            child = %child_name,
                            error = %err,
                            "failed to relay subagent result to parent"
                        );
                        (false, Some(err))
                    }
                },
                Decision::Deny => (false, None),
            };

            let audit_action = Action {
                kind: ActionKind::ToolCall {
                    tool: "SubagentResultReturn".to_string(),
                    args: serde_json::json!({
                        "parent": parent.clone(),
                        "child": child_name,
                        "depth": meta.depth,
                        "exit_code": exit_code,
                        "decision": decision.to_string(),
                        "policy_reason": policy_reason,
                        "delivered": delivered,
                        "delivery_error": delivery_error,
                    }),
                },
                ..policy_action
            };
            let verdict = match decision {
                Decision::Allow if delivered => {
                    Verdict::allow(audit_action.id, "subagent result delivered to parent", None)
                }
                Decision::Allow => Verdict::allow(
                    audit_action.id,
                    "subagent result approved but parent delivery failed",
                    None,
                ),
                Decision::Deny => Verdict::deny(audit_action.id, policy_reason, None),
            };
            self.append_audit_entry(&audit_action, &verdict);
        }
    }

    /// Forward notable fleet events to the notification channel.
    ///
    /// Converts `NotableEvent`s (from `drain_updates`) into `PilotWebhookEvent`s
    /// and sends them through the channel for Telegram delivery.
    fn forward_to_channel(&self, events: Vec<(String, NotableEvent)>) {
        let tx = match &self.channel_tx {
            Some(tx) => tx,
            None => return,
        };

        for (agent_name, event) in events {
            let kind = match event {
                NotableEvent::PendingPrompt {
                    request_id,
                    raw_prompt,
                } => PilotEventKind::PendingApproval {
                    request_id,
                    raw_prompt,
                },
                NotableEvent::AttentionNeeded { nudge_count } => {
                    PilotEventKind::AttentionNeeded { nudge_count }
                }
                NotableEvent::StallNudge { nudge_count } => PilotEventKind::StallDetected {
                    nudge_count,
                    idle_secs: 0,
                },
                NotableEvent::ChildExited { exit_code } => {
                    PilotEventKind::AgentExited { exit_code }
                }
            };

            // Build stats from the slot if available
            let stats = self
                .fleet
                .slot(&agent_name)
                .and_then(|s| s.pilot_stats.as_ref())
                .map(|ps| EventStats {
                    approved: ps.approved,
                    denied: ps.denied,
                    uncertain: ps.uncertain,
                    nudges: ps.nudges,
                    uptime_secs: self
                        .fleet
                        .slot(&agent_name)
                        .and_then(|s| s.uptime_secs())
                        .unwrap_or(0),
                })
                .unwrap_or_default();

            let webhook_event = PilotWebhookEvent::new(
                kind,
                &agent_name,
                0, // PID not easily available from slot
                vec![],
                None,
                stats,
            );

            let input = ChannelInput::PilotEvent(webhook_event);
            if tx.send(input).is_err() {
                info!("notification channel closed, stopping event forwarding");
                break;
            }
        }
    }

    /// Handle a single daemon control command.
    fn handle_command(&mut self, cmd: DaemonCommand) -> DaemonResponse {
        match cmd {
            DaemonCommand::Ping => {
                let ping = DaemonPing {
                    uptime_secs: self.uptime_secs(),
                    agent_count: self.fleet.agent_count(),
                    running_count: self.fleet.running_count(),
                    daemon_pid: std::process::id(),
                    policy_engine_loaded: self.policy_engine.is_some(),
                    hook_fail_open: hook_fail_open_enabled(),
                };
                match serde_json::to_value(&ping) {
                    Ok(data) => DaemonResponse::ok_with_data("pong", data),
                    Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                }
            }

            DaemonCommand::ListAgents => {
                let now = std::time::Instant::now();
                let summaries: Vec<AgentSummary> = self
                    .fleet
                    .agent_names_sorted()
                    .iter()
                    .filter_map(|name| {
                        let slot = self.fleet.slot(name)?;
                        // Compute live remaining backoff for Crashed status
                        let status = match &slot.status {
                            AgentStatus::Crashed { exit_code, .. } => {
                                let remaining = slot
                                    .backoff_until
                                    .map(|t| t.saturating_duration_since(now).as_secs())
                                    .unwrap_or(0);
                                AgentStatus::Crashed {
                                    exit_code: *exit_code,
                                    restart_in_secs: remaining,
                                }
                            }
                            other => other.clone(),
                        };
                        let tool = self.fleet.agent_tool_name(name).unwrap_or_default();
                        let config = self.fleet.agent_config(name)?;
                        let fallback = slot
                            .fallback_state
                            .lock()
                            .ok()
                            .and_then(|state| state.clone());
                        Some(AgentSummary {
                            name: name.clone(),
                            status,
                            tool,
                            working_dir: config.working_dir.to_string_lossy().into_owned(),
                            role: config.role.clone(),
                            restart_count: slot.restart_count,
                            pending_count: self.fleet.agent_pending_count(name),
                            attention_needed: self.fleet.agent_attention_needed(name),
                            is_orchestrator: config.orchestrator.is_some(),
                            attach_command: slot.attach_command.clone(),
                            fallback,
                        })
                    })
                    .collect();
                match serde_json::to_value(&summaries) {
                    Ok(data) => DaemonResponse::ok_with_data("agents listed", data),
                    Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                }
            }

            DaemonCommand::AgentStatus { ref name } => {
                let Some(slot) = self.fleet.slot(name) else {
                    return DaemonResponse::error(format!("unknown agent: {name}"));
                };
                let now = std::time::Instant::now();
                let status = match &slot.status {
                    AgentStatus::Crashed { exit_code, .. } => {
                        let remaining = slot
                            .backoff_until
                            .map(|t| t.saturating_duration_since(now).as_secs())
                            .unwrap_or(0);
                        AgentStatus::Crashed {
                            exit_code: *exit_code,
                            restart_in_secs: remaining,
                        }
                    }
                    other => other.clone(),
                };
                let fallback = slot
                    .fallback_state
                    .lock()
                    .ok()
                    .and_then(|state| state.clone());
                let detail = AgentDetail {
                    name: name.clone(),
                    status,
                    tool: self.fleet.agent_tool_name(name).unwrap_or_default(),
                    working_dir: slot.config.working_dir.to_string_lossy().into_owned(),
                    restart_count: slot.restart_count,
                    pid: match &slot.status {
                        AgentStatus::Running { pid } => Some(*pid),
                        _ => None,
                    },
                    uptime_secs: slot.started_at.map(|t| t.elapsed().as_secs()),
                    session_id: slot
                        .session_id
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .map(|u| u.to_string()),
                    role: slot.config.role.clone(),
                    agent_goal: slot.config.agent_goal.clone(),
                    context: slot.config.context.clone(),
                    task: slot.config.task.clone(),
                    enabled: slot.config.enabled,
                    pending_count: slot.pending_prompts.len(),
                    attention_needed: slot.attention_needed,
                    fallback,
                };
                match serde_json::to_value(&detail) {
                    Ok(data) => DaemonResponse::ok_with_data("agent detail", data),
                    Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                }
            }

            DaemonCommand::AgentOutput { ref name, lines } => {
                let line_count = lines.unwrap_or(50);
                match self.fleet.agent_output(name, line_count) {
                    Ok(output) => match serde_json::to_value(&output) {
                        Ok(data) => DaemonResponse::ok_with_data("output", data),
                        Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                    },
                    Err(e) => DaemonResponse::error(e),
                }
            }

            DaemonCommand::SessionList => {
                let sessions: Vec<SessionInfo> = self
                    .fleet
                    .agent_names_sorted()
                    .into_iter()
                    .filter_map(|name| {
                        let slot = self.fleet.slot(&name)?;
                        Some(SessionInfo {
                            session_key: session_key_for_agent(&name),
                            agent: name,
                            is_orchestrator: slot.config.orchestrator.is_some(),
                            parent: self
                                .subagents
                                .get(&slot.config.name)
                                .map(|s| s.parent.clone()),
                        })
                    })
                    .collect();
                match serde_json::to_value(&sessions) {
                    Ok(data) => DaemonResponse::ok_with_data("session list", data),
                    Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                }
            }
            DaemonCommand::SessionHistory {
                ref session_key,
                lines,
            } => {
                let Some(agent) = parse_session_key(session_key) else {
                    return DaemonResponse::error(format!("invalid session key: {session_key}"));
                };
                let limit = lines.unwrap_or(50);
                match self.fleet.agent_output(&agent, limit) {
                    Ok(output) => {
                        let history = SessionHistory {
                            session_key: session_key.clone(),
                            lines: output,
                        };
                        match serde_json::to_value(&history) {
                            Ok(data) => DaemonResponse::ok_with_data("session history", data),
                            Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                        }
                    }
                    Err(e) => DaemonResponse::error(e),
                }
            }
            DaemonCommand::SessionSend {
                ref session_key,
                ref text,
            } => {
                let Some(agent) = parse_session_key(session_key) else {
                    return DaemonResponse::error(format!("invalid session key: {session_key}"));
                };
                match self.fleet.send_to_agent(&agent, text) {
                    Ok(()) => DaemonResponse::ok(format!("sent to '{session_key}'")),
                    Err(e) => DaemonResponse::error(e),
                }
            }

            DaemonCommand::StartAgent { ref name } => {
                match self.fleet.agent_status(name) {
                    None => return DaemonResponse::error(format!("unknown agent: {name}")),
                    Some(&AgentStatus::Disabled) => {
                        return DaemonResponse::error(format!(
                            "agent '{name}' is disabled. Use enable first."
                        ));
                    }
                    _ => {}
                }
                self.fleet.start_agent(name);
                DaemonResponse::ok(format!("agent '{name}' starting"))
            }

            DaemonCommand::StopAgent { ref name } => {
                if self.fleet.agent_status(name).is_none() {
                    return DaemonResponse::error(format!("unknown agent: {name}"));
                }
                self.fleet.stop_agent(name);
                DaemonResponse::ok(format!("stopping '{name}'"))
            }

            DaemonCommand::RestartAgent { ref name } => match self.fleet.restart_agent(name) {
                Ok(()) => DaemonResponse::ok(format!("restarting '{name}'")),
                Err(e) => DaemonResponse::error(e),
            },

            DaemonCommand::SendToAgent { ref name, ref text } => {
                match self.fleet.send_to_agent(name, text) {
                    Ok(()) => DaemonResponse::ok(format!("sent to '{name}'")),
                    Err(e) => DaemonResponse::error(e),
                }
            }

            DaemonCommand::AddAgent { ref config, start } => {
                let name = config.name.clone();
                // Validate agent name to prevent path traversal and injection.
                if let Err(e) = aegis_types::validate_config_name(&name) {
                    return DaemonResponse::error(format!("invalid agent name: {e}"));
                }
                if self.fleet.agent_status(&name).is_some() {
                    return DaemonResponse::error(format!("agent '{name}' already exists"));
                }
                // Validate working directory at the API boundary for immediate feedback.
                if !config.working_dir.is_dir() {
                    return DaemonResponse::error(format!(
                        "working directory '{}' does not exist or is not a directory",
                        config.working_dir.display()
                    ));
                }
                let slot_config: AgentSlotConfig = *config.clone();

                // Persist first: build candidate config and write to disk
                // before mutating in-memory state.
                let mut candidate = self.config.clone();
                candidate.agents.push(slot_config.clone());
                if let Err(e) = Self::persist_config_to_disk(&candidate) {
                    return DaemonResponse::error(format!("failed to save config: {e}"));
                }

                // Disk write succeeded -- now safe to update memory
                self.config = candidate;
                self.fleet.add_agent(slot_config);
                if start {
                    self.fleet.start_agent(&name);
                }
                DaemonResponse::ok(format!("agent '{name}' added"))
            }

            DaemonCommand::SpawnSubagent { ref request } => {
                match self.spawn_subagent(request.clone()) {
                    Ok(result) => match serde_json::to_value(result) {
                        Ok(data) => DaemonResponse::ok_with_data("subagent spawned", data),
                        Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                    },
                    Err(e) => DaemonResponse::error(e),
                }
            }

            DaemonCommand::RemoveAgent { ref name } => {
                if self.fleet.agent_status(name).is_none() {
                    return DaemonResponse::error(format!("unknown agent: {name}"));
                }

                // Persist first: build candidate config without the agent
                let mut candidate = self.config.clone();
                candidate.agents.retain(|a| a.name != *name);
                if let Err(e) = Self::persist_config_to_disk(&candidate) {
                    return DaemonResponse::error(format!("failed to save config: {e}"));
                }

                // Disk write succeeded -- now safe to update memory
                self.config = candidate;
                self.remove_subagent_descendants(name);
                self.cleanup_agent_runtime_state(name);
                self.fleet.remove_agent(name); // remove_agent stops the agent internally
                self.subagents.remove(name);
                DaemonResponse::ok(format!("agent '{name}' removed"))
            }

            DaemonCommand::ApproveRequest {
                ref name,
                ref request_id,
            } => {
                let id = match uuid::Uuid::parse_str(request_id) {
                    Ok(id) => id,
                    Err(e) => return DaemonResponse::error(format!("invalid request_id: {e}")),
                };
                match self.fleet.approve_request(name, id) {
                    Ok(()) => {
                        DaemonResponse::ok(format!("approved request {request_id} for '{name}'"))
                    }
                    Err(e) => DaemonResponse::error(e),
                }
            }

            DaemonCommand::DenyRequest {
                ref name,
                ref request_id,
            } => {
                let id = match uuid::Uuid::parse_str(request_id) {
                    Ok(id) => id,
                    Err(e) => return DaemonResponse::error(format!("invalid request_id: {e}")),
                };
                match self.fleet.deny_request(name, id) {
                    Ok(()) => {
                        DaemonResponse::ok(format!("denied request {request_id} for '{name}'"))
                    }
                    Err(e) => DaemonResponse::error(e),
                }
            }

            DaemonCommand::NudgeAgent {
                ref name,
                ref message,
            } => match self.fleet.nudge_agent(name, message.clone()) {
                Ok(()) => DaemonResponse::ok(format!("nudged '{name}'")),
                Err(e) => DaemonResponse::error(e),
            },

            DaemonCommand::ListPending { ref name } => match self.fleet.list_pending(name) {
                Ok(pending) => {
                    let summaries: Vec<PendingPromptSummary> = pending
                        .iter()
                        .map(|p| PendingPromptSummary {
                            request_id: p.request_id.to_string(),
                            raw_prompt: p.raw_prompt.clone(),
                            age_secs: p.received_at.elapsed().as_secs(),
                        })
                        .collect();
                    match serde_json::to_value(&summaries) {
                        Ok(data) => DaemonResponse::ok_with_data("pending prompts", data),
                        Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                    }
                }
                Err(e) => DaemonResponse::error(e),
            },

            DaemonCommand::EvaluateToolUse {
                ref agent,
                ref tool_name,
                ref tool_input,
            } => {
                let slot = self.fleet.slot(agent);
                let is_openclaw_agent = slot
                    .as_ref()
                    .map(|s| matches!(s.config.tool, AgentToolConfig::OpenClaw { .. }))
                    .unwrap_or(false);
                if is_openclaw_agent {
                    let bridge_connected = slot
                        .as_ref()
                        .map(|s| hooks::openclaw_bridge_connected(&s.config.working_dir))
                        .unwrap_or(false);
                    if !bridge_connected {
                        let tool_verdict = ToolUseVerdict {
                            decision: "deny".to_string(),
                            reason: "secure runtime bridge unavailable; action denied by fail-closed policy".to_string(),
                        };
                        return match serde_json::to_value(&tool_verdict) {
                            Ok(data) => DaemonResponse::ok_with_data("deny", data),
                            Err(e) => {
                                DaemonResponse::error(format!("serialization failed: {e}"))
                            }
                        };
                    }
                    if !is_known_policy_tool(tool_name) {
                        let tool_verdict = ToolUseVerdict {
                            decision: "deny".to_string(),
                            reason: format!(
                                "unmapped runtime tool '{tool_name}' denied by fail-closed policy"
                            ),
                        };
                        return match serde_json::to_value(&tool_verdict) {
                            Ok(data) => DaemonResponse::ok_with_data("deny", data),
                            Err(e) => {
                                DaemonResponse::error(format!("serialization failed: {e}"))
                            }
                        };
                    }
                }

                // Interactive tools (AskUserQuestion, EnterPlanMode) would stall
                // a headless daemon-managed agent. Deny them with a contextual
                // prompt so the model proceeds autonomously.
                if is_interactive_tool(tool_name) {
                    let reason = compose_autonomy_prompt(
                        tool_name,
                        self.config.goal.as_deref(),
                        self.fleet.slot(agent).map(|s| &s.config),
                    );
                    info!(
                        agent = %agent, tool = %tool_name,
                        decision = "deny", reason = "interactive tool blocked",
                        "hook policy evaluation"
                    );
                    let tool_verdict = ToolUseVerdict {
                        decision: "deny".to_string(),
                        reason,
                    };
                    return match serde_json::to_value(&tool_verdict) {
                        Ok(data) => DaemonResponse::ok_with_data("deny", data),
                        Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                    };
                }

                let action_kind = map_tool_use_to_action(tool_name, tool_input);
                let action = Action::new(agent.clone(), action_kind);

                let (decision_str, reason) = match &self.policy_engine {
                    Some(engine) => {
                        let verdict = engine.evaluate(&action);
                        let d = match verdict.decision {
                            Decision::Allow => "allow",
                            Decision::Deny => "deny",
                        };
                        (d.to_string(), verdict.reason)
                    }
                    None => {
                        if hook_fail_open_enabled() {
                            (
                                "allow".to_string(),
                                "policy engine unavailable; allowed due to AEGIS_HOOK_FAIL_OPEN"
                                    .to_string(),
                            )
                        } else {
                            (
                                "deny".to_string(),
                                "policy engine unavailable; denied by fail-closed hook policy"
                                    .to_string(),
                            )
                        }
                    }
                };

                info!(
                    agent = %agent, tool = %tool_name,
                    decision = %decision_str, reason = %reason,
                    "hook policy evaluation"
                );

                let tool_verdict = ToolUseVerdict {
                    decision: decision_str.clone(),
                    reason,
                };
                match serde_json::to_value(&tool_verdict) {
                    Ok(data) => DaemonResponse::ok_with_data(&decision_str, data),
                    Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                }
            }

            DaemonCommand::RuntimeCapabilities { ref name } => {
                let slot = match self.fleet.slot(name) {
                    Some(s) => s,
                    None => return DaemonResponse::error(format!("unknown agent: {name}")),
                };
                let mut caps = runtime_capabilities(&slot.config);
                caps.toolkit_capture_enabled = self.config.toolkit.capture.enabled;
                caps.toolkit_input_enabled = self.config.toolkit.input.enabled;
                caps.toolkit_browser_enabled = self.config.toolkit.browser.enabled;
                caps.toolkit_browser_backend = self.config.toolkit.browser.backend.clone();
                caps.loop_max_micro_actions = self.config.toolkit.loop_executor.max_micro_actions;
                caps.loop_time_budget_ms = self.config.toolkit.loop_executor.time_budget_ms;
                caps.tool_contract = render_orchestrator_tool_contract(name, &self.config.toolkit);
                if let Some(session) = self.capture_sessions.get(name) {
                    caps.active_capture_session_id = Some(session.session_id.clone());
                    caps.active_capture_target_fps = Some(session.target_fps);
                }
                if let Some(last) = self.last_tool_actions.get(name) {
                    caps.last_tool_action = Some(last.result.action.clone());
                    caps.last_tool_risk_tag = Some(last.risk_tag);
                    caps.last_tool_note = last.result.note.clone();
                    caps.last_tool_decision = last
                        .result
                        .note
                        .as_deref()
                        .map(|n| {
                            if n.starts_with("allow:") {
                                "allow"
                            } else {
                                "deny"
                            }
                        })
                        .map(str::to_string);
                }
                match serde_json::to_value(&caps) {
                    Ok(data) => DaemonResponse::ok_with_data("runtime capabilities", data),
                    Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                }
            }

            DaemonCommand::ParityStatus => match parity_status_report() {
                Ok(report) => match serde_json::to_value(report) {
                    Ok(data) => DaemonResponse::ok_with_data("secure-runtime status", data),
                    Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                },
                Err(e) => DaemonResponse::error(e),
            },

            DaemonCommand::ParityDiff => match parity_diff_report() {
                Ok(report) => match serde_json::to_value(report) {
                    Ok(data) => DaemonResponse::ok_with_data("secure-runtime diff", data),
                    Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                },
                Err(e) => DaemonResponse::error(e),
            },

            DaemonCommand::ParityVerify => match parity_verify_report() {
                Ok(report) => {
                    let msg = if report.ok {
                        "secure-runtime verification passed"
                    } else {
                        "secure-runtime verification failed"
                    };
                    match serde_json::to_value(report) {
                        Ok(data) => DaemonResponse::ok_with_data(msg, data),
                        Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                    }
                }
                Err(e) => DaemonResponse::error(e),
            },

            DaemonCommand::StopBrowserProfile {
                ref name,
                ref session_id,
            } => self.handle_command(DaemonCommand::ExecuteToolAction {
                name: name.clone(),
                action: ToolAction::BrowserProfileStop {
                    session_id: session_id.clone(),
                },
            }),

            DaemonCommand::ExecuteToolAction {
                ref name,
                ref action,
            } => {
                let slot = match self.fleet.slot(name) {
                    Some(slot) => slot,
                    None => return DaemonResponse::error(format!("unknown agent: {name}")),
                };

                let mapping = map_tool_action(action);
                if matches!(slot.config.tool, AgentToolConfig::OpenClaw { .. })
                    && !hooks::openclaw_bridge_connected(&slot.config.working_dir)
                {
                    let deny_reason =
                        "secure runtime bridge unavailable; action denied by fail-closed policy";
                    let execution = ToolActionExecution {
                        result: aegis_toolkit::contract::ToolResult {
                            action: mapping.cedar_action.to_string(),
                            risk_tag: mapping.risk_tag,
                            capture_latency_ms: None,
                            input_latency_ms: None,
                            frame_id: None,
                            window_id: None,
                            session_id: self
                                .capture_sessions
                                .get(name)
                                .map(|s| s.session_id.clone()),
                            note: Some(format!("deny: {deny_reason}")),
                        },
                        risk_tag: mapping.risk_tag,
                    };
                    self.last_tool_actions
                        .insert(name.clone(), execution.clone());
                    let fallback_action = Action::new(
                        name.clone(),
                        ActionKind::ToolCall {
                            tool: mapping.cedar_action.to_string(),
                            args: serde_json::json!({ "bridge_connected": false }),
                        },
                    );
                    self.append_runtime_audit(
                        fallback_action,
                        self.runtime_provenance(
                            name,
                            RuntimeOperation::ExecuteToolAction,
                            action,
                            "deny",
                            deny_reason,
                            &execution,
                        ),
                    );
                    let data = serde_json::to_value(ToolActionOutcome {
                        execution,
                        frame: None,
                        tui: None,
                        browser: None,
                    })
                    .unwrap_or(serde_json::Value::Null);
                    return DaemonResponse::ok_with_data("deny", data);
                }

                if let Err(precheck_reason) = self.precheck_tool_action(action) {
                    let execution = ToolActionExecution {
                        result: aegis_toolkit::contract::ToolResult {
                            action: mapping.cedar_action.to_string(),
                            risk_tag: mapping.risk_tag,
                            capture_latency_ms: None,
                            input_latency_ms: None,
                            frame_id: None,
                            window_id: None,
                            session_id: self
                                .capture_sessions
                                .get(name)
                                .map(|s| s.session_id.clone()),
                            note: Some(format!("deny: {precheck_reason}")),
                        },
                        risk_tag: mapping.risk_tag,
                    };
                    self.last_tool_actions
                        .insert(name.clone(), execution.clone());
                    let fallback_action = Action::new(
                        name.clone(),
                        ActionKind::ToolCall {
                            tool: mapping.cedar_action.to_string(),
                            args: serde_json::json!({ "precheck": true }),
                        },
                    );
                    self.append_runtime_audit(
                        fallback_action,
                        self.runtime_provenance(
                            name,
                            RuntimeOperation::ExecuteToolAction,
                            action,
                            "deny",
                            &precheck_reason,
                            &execution,
                        ),
                    );
                    let data = serde_json::to_value(ToolActionOutcome {
                        execution,
                        frame: None,
                        tui: None,
                        browser: None,
                    })
                    .unwrap_or(serde_json::Value::Null);
                    return DaemonResponse::ok_with_data("deny", data);
                }
                let (cedar_action, decision, reason) =
                    self.evaluate_runtime_tool_action(name, action);

                if decision == "deny" {
                    let execution = ToolActionExecution {
                        result: aegis_toolkit::contract::ToolResult {
                            action: mapping.cedar_action.to_string(),
                            risk_tag: mapping.risk_tag,
                            capture_latency_ms: None,
                            input_latency_ms: None,
                            frame_id: None,
                            window_id: None,
                            session_id: self
                                .capture_sessions
                                .get(name)
                                .map(|s| s.session_id.clone()),
                            note: Some(format!("deny: {reason}")),
                        },
                        risk_tag: mapping.risk_tag,
                    };

                    self.last_tool_actions
                        .insert(name.clone(), execution.clone());
                    self.append_runtime_audit(
                        cedar_action.clone(),
                        self.runtime_provenance(
                            name,
                            RuntimeOperation::ExecuteToolAction,
                            action,
                            "deny",
                            &reason,
                            &execution,
                        ),
                    );

                    let data = serde_json::to_value(ToolActionOutcome {
                        execution,
                        frame: None,
                        tui: None,
                        browser: None,
                    })
                    .unwrap_or(serde_json::Value::Null);
                    return DaemonResponse::ok_with_data("deny", data);
                }

                if let ToolAction::ScreenCapture { region, .. } = action {
                    if let Some(cached) = self.latest_cached_frame(name, region) {
                        let age_ms = cached.captured_at.elapsed().as_millis() as u64;
                        let execution = ToolActionExecution {
                            result: aegis_toolkit::contract::ToolResult {
                                action: mapping.cedar_action.to_string(),
                                risk_tag: mapping.risk_tag,
                                capture_latency_ms: Some(age_ms),
                                input_latency_ms: None,
                                frame_id: Some(cached.frame_id),
                                window_id: None,
                                session_id: self
                                    .capture_sessions
                                    .get(name)
                                    .map(|s| s.session_id.clone()),
                                note: Some(format!("allow: {reason} (cached {}ms)", age_ms)),
                            },
                            risk_tag: mapping.risk_tag,
                        };
                        self.last_tool_actions
                            .insert(name.clone(), execution.clone());
                        self.append_runtime_audit(
                            cedar_action.clone(),
                            self.runtime_provenance(
                                name,
                                RuntimeOperation::ExecuteToolAction,
                                action,
                                "allow",
                                &reason,
                                &execution,
                            ),
                        );
                        let data = serde_json::to_value(ToolActionOutcome {
                            execution,
                            frame: Some(cached.payload),
                            tui: None,
                            browser: None,
                        })
                        .unwrap_or(serde_json::Value::Null);
                        return DaemonResponse::ok_with_data("allow", data);
                    }
                }

                if self.toolkit_runtime.is_none() {
                    match ToolkitRuntime::new(&self.config.toolkit) {
                        Ok(rt) => self.toolkit_runtime = Some(rt),
                        Err(e) => {
                            let execution = ToolActionExecution {
                                result: aegis_toolkit::contract::ToolResult {
                                    action: mapping.cedar_action.to_string(),
                                    risk_tag: mapping.risk_tag,
                                    capture_latency_ms: None,
                                    input_latency_ms: None,
                                    frame_id: None,
                                    window_id: None,
                                    session_id: self
                                        .capture_sessions
                                        .get(name)
                                        .map(|s| s.session_id.clone()),
                                    note: Some(format!("deny: runtime unavailable ({e})")),
                                },
                                risk_tag: mapping.risk_tag,
                            };
                            self.last_tool_actions
                                .insert(name.clone(), execution.clone());
                            let denied_reason = format!("runtime unavailable ({e})");
                            self.append_runtime_audit(
                                cedar_action.clone(),
                                self.runtime_provenance(
                                    name,
                                    RuntimeOperation::ExecuteToolAction,
                                    action,
                                    "deny",
                                    &denied_reason,
                                    &execution,
                                ),
                            );
                            let data = serde_json::to_value(ToolActionOutcome {
                                execution,
                                frame: None,
                                tui: None,
                                browser: match action {
                                    ToolAction::BrowserNavigate { session_id, .. }
                                    | ToolAction::BrowserEvaluate { session_id, .. }
                                    | ToolAction::BrowserClick { session_id, .. }
                                    | ToolAction::BrowserType { session_id, .. }
                                    | ToolAction::BrowserSnapshot { session_id, .. }
                                    | ToolAction::BrowserProfileStart { session_id, .. }
                                    | ToolAction::BrowserProfileStop { session_id, .. } => {
                                        Some(BrowserToolData {
                                            session_id: session_id.clone(),
                                            backend: "cdp".to_string(),
                                            available: false,
                                            note: "browser backend unavailable".to_string(),
                                            screenshot_base64: None,
                                            ws_url: self.config.toolkit.browser.cdp_ws_url.clone(),
                                            result_json: None,
                                        })
                                    }
                                    _ => None,
                                },
                            })
                            .unwrap_or(serde_json::Value::Null);
                            return DaemonResponse::ok_with_data("deny", data);
                        }
                    }
                }

                let bridge = FleetTuiBridge {
                    fleet: &self.fleet,
                    default_target: name,
                };
                let mut output: ToolkitOutput = match self
                    .toolkit_runtime
                    .as_mut()
                    .expect("toolkit runtime initialized")
                    .execute_with_tui_bridge(action, Some(&bridge))
                {
                    Ok(output) => output,
                    Err(e) => {
                        let execution = ToolActionExecution {
                            result: aegis_toolkit::contract::ToolResult {
                                action: mapping.cedar_action.to_string(),
                                risk_tag: mapping.risk_tag,
                                capture_latency_ms: None,
                                input_latency_ms: None,
                                frame_id: None,
                                window_id: None,
                                session_id: self
                                    .capture_sessions
                                    .get(name)
                                    .map(|s| s.session_id.clone()),
                                note: Some(format!("deny: runtime error ({e})")),
                            },
                            risk_tag: mapping.risk_tag,
                        };
                        self.last_tool_actions
                            .insert(name.clone(), execution.clone());
                        let denied_reason = format!("runtime error ({e})");
                        self.append_runtime_audit(
                            cedar_action.clone(),
                            self.runtime_provenance(
                                name,
                                RuntimeOperation::ExecuteToolAction,
                                action,
                                "deny",
                                &denied_reason,
                                &execution,
                            ),
                        );
                        let data = serde_json::to_value(ToolActionOutcome {
                            execution,
                            frame: None,
                            tui: None,
                            browser: match action {
                                ToolAction::BrowserNavigate { session_id, .. }
                                | ToolAction::BrowserEvaluate { session_id, .. }
                                | ToolAction::BrowserClick { session_id, .. }
                                | ToolAction::BrowserType { session_id, .. }
                                | ToolAction::BrowserSnapshot { session_id, .. }
                                | ToolAction::BrowserProfileStart { session_id, .. }
                                | ToolAction::BrowserProfileStop { session_id, .. } => {
                                    Some(BrowserToolData {
                                        session_id: session_id.clone(),
                                        backend: "cdp".to_string(),
                                        available: false,
                                        note: "browser action denied: CDP backend unavailable"
                                            .to_string(),
                                        screenshot_base64: None,
                                        ws_url: self.config.toolkit.browser.cdp_ws_url.clone(),
                                        result_json: None,
                                    })
                                }
                                _ => None,
                            },
                        })
                        .unwrap_or(serde_json::Value::Null);
                        return DaemonResponse::ok_with_data("deny", data);
                    }
                };

                output.execution.result.note = Some(format!("allow: {reason}"));
                self.last_tool_actions
                    .insert(name.clone(), output.execution.clone());
                self.append_runtime_audit(
                    cedar_action.clone(),
                    self.runtime_provenance(
                        name,
                        RuntimeOperation::ExecuteToolAction,
                        action,
                        "allow",
                        &reason,
                        &output.execution,
                    ),
                );

                let data = serde_json::to_value(ToolActionOutcome {
                    execution: output.execution,
                    frame: output.frame,
                    tui: output.tui,
                    browser: output.browser,
                })
                .unwrap_or(serde_json::Value::Null);
                DaemonResponse::ok_with_data("allow", data)
            }

            DaemonCommand::ExecuteToolBatch {
                ref name,
                ref actions,
                max_actions,
            } => {
                if self.fleet.slot(name).is_none() {
                    return DaemonResponse::error(format!("unknown agent: {name}"));
                }
                if actions.is_empty() {
                    let empty = ToolBatchOutcome {
                        executed: 0,
                        outcomes: vec![],
                        halted_reason: Some("empty action batch".to_string()),
                    };
                    return DaemonResponse::ok_with_data(
                        "batch halted",
                        serde_json::to_value(empty).unwrap_or(serde_json::Value::Null),
                    );
                }

                let configured_limit = self.config.toolkit.loop_executor.max_micro_actions.max(1);
                let requested_limit = max_actions.unwrap_or(configured_limit).max(1);
                let hard_limit = requested_limit.min(configured_limit);
                let mut outcomes = Vec::new();
                let started = Instant::now();
                let mut halted_reason: Option<String> = None;

                for action in actions.iter().take(usize::from(hard_limit)) {
                    if self.config.toolkit.loop_executor.halt_on_high_risk
                        && matches!(map_tool_action(action).risk_tag, RiskTag::High)
                    {
                        halted_reason = Some(format!(
                            "policy boundary reached before high-risk action {}",
                            action.policy_action_name()
                        ));
                        break;
                    }
                    if started.elapsed().as_millis() as u64
                        > self.config.toolkit.loop_executor.time_budget_ms
                    {
                        halted_reason = Some(format!(
                            "time budget exceeded ({}ms)",
                            self.config.toolkit.loop_executor.time_budget_ms
                        ));
                        break;
                    }

                    let response = self.handle_command(DaemonCommand::ExecuteToolAction {
                        name: name.clone(),
                        action: action.clone(),
                    });
                    if !response.ok {
                        halted_reason = Some(response.message.clone());
                        break;
                    }
                    let Some(data) = response.data else {
                        halted_reason = Some("missing action outcome data".to_string());
                        break;
                    };
                    let outcome: ToolActionOutcome = match serde_json::from_value(data) {
                        Ok(outcome) => outcome,
                        Err(e) => {
                            halted_reason = Some(format!("invalid action outcome: {e}"));
                            break;
                        }
                    };
                    let denied = outcome
                        .execution
                        .result
                        .note
                        .as_deref()
                        .map(|note| note.starts_with("deny:"))
                        .unwrap_or(false);
                    outcomes.push(outcome);
                    if denied {
                        halted_reason = Some("batch halted on denied action".to_string());
                        break;
                    }
                }

                if outcomes.len() == usize::from(hard_limit)
                    && actions.len() > outcomes.len()
                    && halted_reason.is_none()
                {
                    halted_reason = Some(format!("batch cap reached ({hard_limit} actions)"));
                }

                let batch = ToolBatchOutcome {
                    executed: outcomes.len(),
                    outcomes,
                    halted_reason,
                };
                DaemonResponse::ok_with_data(
                    "batch executed",
                    serde_json::to_value(batch).unwrap_or(serde_json::Value::Null),
                )
            }

            DaemonCommand::StartCaptureSession {
                ref name,
                ref request,
            } => {
                if self.fleet.slot(name).is_none() {
                    return DaemonResponse::error(format!("unknown agent: {name}"));
                }
                if !self.config.toolkit.capture.enabled {
                    return DaemonResponse::error(
                        "capture start denied: capture actions are disabled by daemon toolkit config",
                    );
                }
                if request.target_fps < self.config.toolkit.capture.min_fps
                    || request.target_fps > self.config.toolkit.capture.max_fps
                {
                    return DaemonResponse::error(format!(
                        "capture start denied: fps {} outside allowed range {}..={}",
                        request.target_fps,
                        self.config.toolkit.capture.min_fps,
                        self.config.toolkit.capture.max_fps
                    ));
                }
                let screen_action = ToolAction::ScreenCapture {
                    region: request.region.as_ref().map(|r| ToolkitCaptureRegion {
                        x: r.x,
                        y: r.y,
                        width: r.width,
                        height: r.height,
                    }),
                    target_fps: request.target_fps,
                };
                let risk = map_tool_action(&screen_action).risk_tag;
                let (cedar_action, decision, reason) =
                    self.evaluate_runtime_tool_action(name, &screen_action);
                if decision == "deny" {
                    let execution = ToolActionExecution {
                        result: aegis_toolkit::contract::ToolResult {
                            action: "CaptureStart".to_string(),
                            risk_tag: risk,
                            capture_latency_ms: None,
                            input_latency_ms: None,
                            frame_id: None,
                            window_id: None,
                            session_id: None,
                            note: Some(format!("deny: {reason}")),
                        },
                        risk_tag: risk,
                    };
                    self.last_tool_actions
                        .insert(name.clone(), execution.clone());
                    self.append_runtime_audit(
                        cedar_action,
                        self.runtime_provenance(
                            name,
                            RuntimeOperation::StartCaptureSession,
                            &screen_action,
                            "deny",
                            &reason,
                            &execution,
                        ),
                    );
                    return DaemonResponse::error(format!("capture start denied: {reason}"));
                }

                let session = CaptureSessionStarted {
                    session_id: format!("cap-{}", uuid::Uuid::new_v4()),
                    target_fps: request.target_fps,
                };
                self.capture_sessions.insert(name.clone(), session.clone());
                let stream_region = request.region.as_ref().map(|r| ToolkitCaptureRegion {
                    x: r.x,
                    y: r.y,
                    width: r.width,
                    height: r.height,
                });
                if let Err(e) = self.spawn_capture_stream(name, &session, stream_region) {
                    warn!(error = %e, "failed to start capture stream");
                }
                let execution = ToolActionExecution {
                    result: aegis_toolkit::contract::ToolResult {
                        action: "CaptureStart".to_string(),
                        risk_tag: risk,
                        capture_latency_ms: None,
                        input_latency_ms: None,
                        frame_id: None,
                        window_id: None,
                        session_id: Some(session.session_id.clone()),
                        note: Some(format!("allow: {reason}")),
                    },
                    risk_tag: risk,
                };
                self.last_tool_actions
                    .insert(name.clone(), execution.clone());
                self.append_runtime_audit(
                    cedar_action,
                    self.runtime_provenance(
                        name,
                        RuntimeOperation::StartCaptureSession,
                        &screen_action,
                        "allow",
                        &reason,
                        &execution,
                    ),
                );
                match serde_json::to_value(&session) {
                    Ok(data) => DaemonResponse::ok_with_data("capture session started", data),
                    Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                }
            }

            DaemonCommand::StopCaptureSession {
                ref name,
                ref session_id,
            } => {
                if self.fleet.slot(name).is_none() {
                    return DaemonResponse::error(format!("unknown agent: {name}"));
                }
                if !self.config.toolkit.capture.enabled {
                    return DaemonResponse::error(
                        "capture stop denied: capture actions are disabled by daemon toolkit config",
                    );
                }
                let target_fps = self
                    .capture_sessions
                    .get(name)
                    .map(|s| s.target_fps)
                    .unwrap_or_default();
                let stop_action = ToolAction::ScreenCapture {
                    region: None,
                    target_fps,
                };
                let risk = map_tool_action(&stop_action).risk_tag;
                let (cedar_action, decision, reason) =
                    self.evaluate_runtime_tool_action(name, &stop_action);
                if decision == "deny" {
                    let execution = ToolActionExecution {
                        result: aegis_toolkit::contract::ToolResult {
                            action: "CaptureStop".to_string(),
                            risk_tag: risk,
                            capture_latency_ms: None,
                            input_latency_ms: None,
                            frame_id: None,
                            window_id: None,
                            session_id: Some(session_id.clone()),
                            note: Some(format!("deny: {reason}")),
                        },
                        risk_tag: risk,
                    };
                    self.last_tool_actions
                        .insert(name.clone(), execution.clone());
                    self.append_runtime_audit(
                        cedar_action,
                        self.runtime_provenance(
                            name,
                            RuntimeOperation::StopCaptureSession,
                            &stop_action,
                            "deny",
                            &reason,
                            &execution,
                        ),
                    );
                    return DaemonResponse::error(format!("capture stop denied: {reason}"));
                }
                match self.capture_sessions.get(name) {
                    Some(s) if s.session_id == *session_id => {
                        self.capture_sessions.remove(name);
                        self.stop_capture_stream(name);
                        let execution = ToolActionExecution {
                            result: aegis_toolkit::contract::ToolResult {
                                action: "CaptureStop".to_string(),
                                risk_tag: risk,
                                capture_latency_ms: None,
                                input_latency_ms: None,
                                frame_id: None,
                                window_id: None,
                                session_id: Some(session_id.clone()),
                                note: Some(format!("allow: {reason}")),
                            },
                            risk_tag: risk,
                        };
                        self.last_tool_actions
                            .insert(name.clone(), execution.clone());
                        self.append_runtime_audit(
                            cedar_action,
                            self.runtime_provenance(
                                name,
                                RuntimeOperation::StopCaptureSession,
                                &stop_action,
                                "allow",
                                &reason,
                                &execution,
                            ),
                        );
                        DaemonResponse::ok("capture session stopped")
                    }
                    Some(_) => {
                        let reason = format!("session mismatch for '{name}': {session_id}");
                        let execution = ToolActionExecution {
                            result: aegis_toolkit::contract::ToolResult {
                                action: "CaptureStop".to_string(),
                                risk_tag: risk,
                                capture_latency_ms: None,
                                input_latency_ms: None,
                                frame_id: None,
                                window_id: None,
                                session_id: Some(session_id.clone()),
                                note: Some(format!("deny: {reason}")),
                            },
                            risk_tag: risk,
                        };
                        self.last_tool_actions
                            .insert(name.clone(), execution.clone());
                        self.append_runtime_audit(
                            cedar_action.clone(),
                            self.runtime_provenance(
                                name,
                                RuntimeOperation::StopCaptureSession,
                                &stop_action,
                                "deny",
                                &reason,
                                &execution,
                            ),
                        );
                        DaemonResponse::error(reason)
                    }
                    None => {
                        let reason = format!("no active capture session for '{name}'");
                        let execution = ToolActionExecution {
                            result: aegis_toolkit::contract::ToolResult {
                                action: "CaptureStop".to_string(),
                                risk_tag: risk,
                                capture_latency_ms: None,
                                input_latency_ms: None,
                                frame_id: None,
                                window_id: None,
                                session_id: Some(session_id.clone()),
                                note: Some(format!("deny: {reason}")),
                            },
                            risk_tag: risk,
                        };
                        self.last_tool_actions
                            .insert(name.clone(), execution.clone());
                        self.append_runtime_audit(
                            cedar_action,
                            self.runtime_provenance(
                                name,
                                RuntimeOperation::StopCaptureSession,
                                &stop_action,
                                "deny",
                                &reason,
                                &execution,
                            ),
                        );
                        DaemonResponse::error(reason)
                    }
                }
            }

            DaemonCommand::LatestCaptureFrame {
                ref name,
                ref region,
            } => {
                if self.fleet.slot(name).is_none() {
                    return DaemonResponse::error(format!("unknown agent: {name}"));
                }
                let region = region.as_ref().map(|r| ToolkitCaptureRegion {
                    x: r.x,
                    y: r.y,
                    width: r.width,
                    height: r.height,
                });
                match self.latest_cached_frame(name, &region) {
                    Some(cached) => {
                        let payload = aegis_control::daemon::LatestCaptureFrame {
                            session_id: self
                                .capture_sessions
                                .get(name)
                                .map(|s| s.session_id.clone()),
                            frame_id: cached.frame_id,
                            age_ms: cached.captured_at.elapsed().as_millis() as u64,
                            frame: cached.payload,
                        };
                        match serde_json::to_value(payload) {
                            Ok(data) => DaemonResponse::ok_with_data("latest frame", data),
                            Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                        }
                    }
                    None => DaemonResponse::error("no cached frame available"),
                }
            }

            DaemonCommand::DashboardStatus => {
                let enabled = self.dashboard_listen.is_some() && self.dashboard_token.is_some();
                let listen = self.dashboard_listen.clone().unwrap_or_default();
                let base_url = if enabled && !listen.is_empty() {
                    Some(format!("http://{listen}"))
                } else {
                    None
                };
                let payload = DashboardStatus {
                    enabled,
                    listen,
                    base_url,
                    token: self.dashboard_token.clone(),
                };
                match serde_json::to_value(payload) {
                    Ok(data) => DaemonResponse::ok_with_data("dashboard status", data),
                    Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                }
            }

            DaemonCommand::DashboardSnapshot => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis();
                let mut agents = Vec::new();
                for name in self.fleet.agent_names_sorted() {
                    let status = self
                        .fleet
                        .agent_status(&name)
                        .map(status_label)
                        .unwrap_or_else(|| "unknown".to_string());
                    let tool = self
                        .fleet
                        .agent_tool_name(&name)
                        .unwrap_or_else(|| "unknown".to_string());
                    let config = self.fleet.agent_config(&name);
                    let role = config.and_then(|c| c.role.clone());
                    let goal = config.and_then(|c| c.agent_goal.clone());

                    let pending_prompts = match self.fleet.list_pending(&name) {
                        Ok(list) => list
                            .iter()
                            .take(3)
                            .map(|p| DashboardPendingPrompt {
                                request_id: p.request_id.to_string(),
                                raw_prompt: p.raw_prompt.clone(),
                                received_at_ms: p.received_at.elapsed().as_millis(),
                            })
                            .collect(),
                        Err(_) => Vec::new(),
                    };
                    let pending_count = self.fleet.agent_pending_count(&name);

                    let last_output = self.fleet.agent_output(&name, 50).unwrap_or_default();

                    let (last_tool_action, last_tool_decision, last_tool_note) =
                        if let Some(last) = self.last_tool_actions.get(&name) {
                            let decision = last.result.note.as_deref().map(|note| {
                                if note.starts_with("allow:") {
                                    "allow".to_string()
                                } else {
                                    "deny".to_string()
                                }
                            });
                            (
                                Some(last.result.action.clone()),
                                decision,
                                last.result.note.clone(),
                            )
                        } else {
                            (None, None, None)
                        };

                    let latest_frame_age_ms = self
                        .latest_cached_frame_any(&name)
                        .map(|f| f.captured_at.elapsed().as_millis() as u64);
                    let fallback = self
                        .fleet
                        .slot(&name)
                        .and_then(|slot| slot.fallback_state.lock().ok().and_then(|s| s.clone()));

                    agents.push(DashboardAgent {
                        name,
                        status,
                        tool,
                        role,
                        goal,
                        pending_count,
                        pending_prompts,
                        last_tool_action,
                        last_tool_decision,
                        last_tool_note,
                        last_output,
                        latest_frame_age_ms,
                        fallback,
                    });
                }
                let snapshot = DashboardSnapshot {
                    timestamp_ms: now,
                    agents,
                };
                match serde_json::to_value(snapshot) {
                    Ok(data) => DaemonResponse::ok_with_data("dashboard snapshot", data),
                    Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                }
            }
            DaemonCommand::TelegramSnapshot { .. } => DaemonResponse::error(
                "telegram snapshots are not available in the control API; use the Telegram channel",
            ),

            DaemonCommand::FleetGoal { ref goal } => {
                match goal {
                    Some(new_goal) => {
                        let new_goal_val = if new_goal.is_empty() {
                            None
                        } else {
                            Some(new_goal.clone())
                        };
                        let display = new_goal_val
                            .clone()
                            .unwrap_or_else(|| "(cleared)".to_string());

                        // Persist first
                        let mut candidate = self.config.clone();
                        candidate.goal = new_goal_val.clone();
                        if let Err(e) = Self::persist_config_to_disk(&candidate) {
                            return DaemonResponse::error(format!("failed to persist goal: {e}"));
                        }

                        // Disk write succeeded -- update memory
                        self.config = candidate;
                        self.fleet.fleet_goal = new_goal_val;
                        DaemonResponse::ok(format!("fleet goal set: {display}"))
                    }
                    None => DaemonResponse::ok_with_data(
                        "fleet goal",
                        serde_json::json!({ "goal": self.config.goal }),
                    ),
                }
            }

            DaemonCommand::UpdateAgentContext {
                ref name,
                ref role,
                ref agent_goal,
                ref context,
                ref task,
            } => {
                if self.fleet.slot(name).is_none() {
                    return DaemonResponse::error(format!("unknown agent: {name}"));
                }

                // Build candidate config with updated context fields
                let mut candidate = self.config.clone();
                if let Some(cfg) = candidate.agents.iter_mut().find(|a| a.name == *name) {
                    if let Some(r) = role {
                        cfg.role = if r.is_empty() { None } else { Some(r.clone()) };
                    }
                    if let Some(g) = agent_goal {
                        cfg.agent_goal = if g.is_empty() { None } else { Some(g.clone()) };
                    }
                    if let Some(c) = context {
                        cfg.context = if c.is_empty() { None } else { Some(c.clone()) };
                    }
                    if let Some(t) = task {
                        cfg.task = if t.is_empty() { None } else { Some(t.clone()) };
                    }
                }

                // Persist first
                if let Err(e) = Self::persist_config_to_disk(&candidate) {
                    return DaemonResponse::error(format!("failed to persist context: {e}"));
                }

                // Disk write succeeded -- update memory (fleet slot + self.config)
                if let Some(slot) = self.fleet.slot_mut(name) {
                    if let Some(cfg) = candidate.agents.iter().find(|a| a.name == *name) {
                        slot.config.role.clone_from(&cfg.role);
                        slot.config.agent_goal.clone_from(&cfg.agent_goal);
                        slot.config.context.clone_from(&cfg.context);
                        slot.config.task.clone_from(&cfg.task);
                    }
                }
                self.config = candidate;
                DaemonResponse::ok(format!(
                    "context updated for '{name}' (takes effect on next restart)"
                ))
            }

            DaemonCommand::GetAgentContext { ref name } => {
                let slot = match self.fleet.slot(name) {
                    Some(s) => s,
                    None => return DaemonResponse::error(format!("unknown agent: {name}")),
                };
                let data = serde_json::json!({
                    "role": slot.config.role,
                    "agent_goal": slot.config.agent_goal,
                    "context": slot.config.context,
                    "task": slot.config.task,
                });
                DaemonResponse::ok_with_data("agent context", data)
            }

            DaemonCommand::EnableAgent { name } => {
                // Validate first
                match self.fleet.slot(&name) {
                    None => return DaemonResponse::error(format!("unknown agent: {name}")),
                    Some(s) if s.config.enabled => {
                        return DaemonResponse::error(format!("agent '{name}' is already enabled"));
                    }
                    _ => {}
                }

                // Persist first
                let mut candidate = self.config.clone();
                if let Some(cfg) = candidate.agents.iter_mut().find(|a| a.name == name) {
                    cfg.enabled = true;
                }
                if let Err(e) = Self::persist_config_to_disk(&candidate) {
                    return DaemonResponse::error(format!("failed to persist enable: {e}"));
                }

                // Disk write succeeded -- update memory
                self.config = candidate;
                match self.fleet.enable_agent(&name) {
                    Ok(()) => DaemonResponse::ok(format!("agent '{name}' enabled")),
                    Err(e) => DaemonResponse::error(e),
                }
            }

            DaemonCommand::DisableAgent { name } => {
                // Validate first
                match self.fleet.slot(&name) {
                    None => return DaemonResponse::error(format!("unknown agent: {name}")),
                    Some(s) if !s.config.enabled => {
                        return DaemonResponse::error(format!(
                            "agent '{name}' is already disabled"
                        ));
                    }
                    _ => {}
                }

                // Persist first
                let mut candidate = self.config.clone();
                if let Some(cfg) = candidate.agents.iter_mut().find(|a| a.name == name) {
                    cfg.enabled = false;
                }
                if let Err(e) = Self::persist_config_to_disk(&candidate) {
                    return DaemonResponse::error(format!("failed to persist disable: {e}"));
                }

                // Disk write succeeded -- update memory
                self.config = candidate;
                match self.fleet.disable_agent(&name) {
                    Ok(()) => DaemonResponse::ok(format!("agent '{name}' disabled")),
                    Err(e) => DaemonResponse::error(e),
                }
            }

            DaemonCommand::ReloadConfig => self.reload_config(),

            DaemonCommand::OrchestratorContext {
                ref agents,
                output_lines,
            } => {
                let line_count = output_lines.unwrap_or(30);
                let all_names = self.fleet.agent_names_sorted();

                // Determine which agents to include
                let target_names: Vec<&String> = if agents.is_empty() {
                    // All non-orchestrator agents
                    all_names
                        .iter()
                        .filter(|name| {
                            self.fleet
                                .agent_config(name)
                                .map(|c| c.orchestrator.is_none())
                                .unwrap_or(true)
                        })
                        .collect()
                } else {
                    all_names
                        .iter()
                        .filter(|name| agents.contains(name))
                        .collect()
                };

                let agent_views: Vec<OrchestratorAgentView> = target_names
                    .iter()
                    .filter_map(|name| {
                        let slot = self.fleet.slot(name)?;
                        let config = self.fleet.agent_config(name)?;
                        let recent_output = self
                            .fleet
                            .agent_output(name, line_count)
                            .unwrap_or_default();

                        Some(OrchestratorAgentView {
                            name: (*name).clone(),
                            status: slot.status.clone(),
                            role: config.role.clone(),
                            agent_goal: config.agent_goal.clone(),
                            task: config.task.clone(),
                            recent_output,
                            uptime_secs: slot.uptime_secs(),
                            attention_needed: slot.attention_needed,
                            pending_count: slot.pending_prompts.len(),
                        })
                    })
                    .collect();

                let snapshot = OrchestratorSnapshot {
                    fleet_goal: self.config.goal.clone(),
                    agents: agent_views,
                };

                match serde_json::to_value(&snapshot) {
                    Ok(data) => DaemonResponse::ok_with_data("orchestrator context", data),
                    Err(e) => DaemonResponse::error(format!("serialization failed: {e}")),
                }
            }

            DaemonCommand::Shutdown => {
                self.request_shutdown();
                DaemonResponse::ok("shutdown initiated")
            }

            // Wave 3 infrastructure stubs -- handled minimally until full implementation.
            DaemonCommand::MemoryGet { .. }
            | DaemonCommand::MemorySet { .. }
            | DaemonCommand::MemoryDelete { .. }
            | DaemonCommand::MemoryList { .. }
            | DaemonCommand::MemorySearch { .. } => {
                DaemonResponse::error("memory store not yet initialized")
            }
            DaemonCommand::CronList
            | DaemonCommand::CronAdd { .. }
            | DaemonCommand::CronRemove { .. }
            | DaemonCommand::CronTrigger { .. } => {
                DaemonResponse::error("cron scheduler not yet initialized")
            }
            DaemonCommand::LoadPlugin { .. }
            | DaemonCommand::ListPlugins
            | DaemonCommand::UnloadPlugin { .. } => {
                DaemonResponse::error("plugin system not yet initialized")
            }
            DaemonCommand::BroadcastToFleet { .. } => {
                DaemonResponse::error("broadcast not yet implemented")
            }
            DaemonCommand::ListModels => {
                DaemonResponse::error("model listing not yet implemented")
            }
            DaemonCommand::AddAlias { alias, command, args } => {
                match self.alias_registry.add(alias, command, args) {
                    Ok(()) => {
                        let config = self.alias_registry.to_config();
                        DaemonResponse::ok_with_data(
                            "alias added",
                            serde_json::to_value(config).unwrap_or_default(),
                        )
                    }
                    Err(e) => DaemonResponse::error(e),
                }
            }
            DaemonCommand::RemoveAlias { alias } => {
                match self.alias_registry.remove(&alias) {
                    Ok(()) => {
                        let config = self.alias_registry.to_config();
                        DaemonResponse::ok_with_data(
                            "alias removed",
                            serde_json::to_value(config).unwrap_or_default(),
                        )
                    }
                    Err(e) => DaemonResponse::error(e),
                }
            }
            DaemonCommand::ListAliases => {
                let entries: Vec<_> = self.alias_registry.list().into_iter().cloned().collect();
                match serde_json::to_value(&entries) {
                    Ok(data) => DaemonResponse::ok_with_data(
                        format!("{} alias(es)", entries.len()),
                        data,
                    ),
                    Err(e) => DaemonResponse::error(format!("failed to serialize aliases: {e}")),
                }
            }
        }
    }

    /// Signal the daemon to shut down.
    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    /// Get the shutdown flag for external signal handlers.
    pub fn shutdown_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shutdown)
    }

    /// Daemon uptime in seconds.
    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    /// Reload configuration from daemon.toml.
    ///
    /// Adds new agents, updates config for existing agents, and removes
    /// agents no longer in the config file. Running agents are NOT
    /// automatically restarted -- config changes take effect on next start.
    fn reload_config(&mut self) -> DaemonResponse {
        let config_path = aegis_types::daemon::daemon_config_path();
        let content = match std::fs::read_to_string(&config_path) {
            Ok(c) => c,
            Err(e) => return DaemonResponse::error(format!("failed to read daemon.toml: {e}")),
        };
        let new_config = match DaemonConfig::from_toml(&content) {
            Ok(c) => c,
            Err(e) => return DaemonResponse::error(format!("failed to parse daemon.toml: {e}")),
        };

        let mut added = 0usize;
        let mut updated = 0usize;
        let mut removed = 0usize;

        // Collect current agent names
        let current_names: std::collections::HashSet<String> =
            self.fleet.agent_names().into_iter().collect();
        let new_names: std::collections::HashSet<String> =
            new_config.agents.iter().map(|a| a.name.clone()).collect();

        // Remove agents no longer in config
        for name in current_names.difference(&new_names) {
            if self.fleet.agent_status(name).is_none() {
                continue;
            }
            self.remove_subagent_descendants(name);
            self.cleanup_agent_runtime_state(name);
            self.fleet.remove_agent(name);
            self.subagents.remove(name);
            removed += 1;
        }

        // Add or update agents
        let mut started = 0;
        for agent_config in &new_config.agents {
            if current_names.contains(&agent_config.name) {
                self.fleet.update_agent_config(agent_config);
                updated += 1;
            } else {
                self.fleet.add_agent(agent_config.clone());
                // Auto-start newly added enabled agents
                if agent_config.enabled {
                    self.fleet.start_agent(&agent_config.name);
                    started += 1;
                }
                added += 1;
            }
        }

        // Update fleet goal
        self.fleet.fleet_goal = new_config.goal.clone();

        // Update stored config
        self.config = new_config;

        // Reload policy engine (picks up new/changed .cedar files)
        let mut policy_warning: Option<String> = None;
        let policy_dir = self
            .aegis_config
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
            .cloned();
        if let Some(ref dir) = policy_dir {
            match aegis_policy::PolicyEngine::new(dir, None) {
                Ok(engine) => {
                    info!(policy_dir = %dir.display(), "policy engine reloaded");
                    self.policy_engine = Some(engine);
                }
                Err(e) => {
                    warn!(?e, "failed to reload policy engine, keeping previous");
                    policy_warning = Some(format!(" (policy reload failed: {e})"));
                }
            }
        } else if self.policy_engine.is_some() {
            warn!(
                "no policy directory found, clearing policy engine (hook checks now fail-closed)"
            );
            self.policy_engine = None;
        }

        let warning = policy_warning.unwrap_or_default();
        let msg = if started > 0 {
            format!("config reloaded: {added} added ({started} started), {updated} updated, {removed} removed{warning}")
        } else {
            format!("config reloaded: {added} added, {updated} updated, {removed} removed{warning}")
        };
        DaemonResponse::ok(msg)
    }

    /// Persist a config to daemon.toml.
    ///
    /// Uses atomic write (write to temp file, then rename) to prevent
    /// corruption if the process is interrupted mid-write.
    ///
    /// Accepts the config to write explicitly so callers can build a
    /// candidate config, persist it, and only then update in-memory state.
    /// This prevents memory/disk divergence if the write fails.
    fn persist_config_to_disk(config: &DaemonConfig) -> Result<(), String> {
        use std::sync::atomic::AtomicU64;
        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let toml_str = config.to_toml().map_err(|e| e.to_string())?;
        let config_path = aegis_types::daemon::daemon_config_path();

        // Ensure the daemon directory exists (handles fresh installs, CI,
        // and recovery if someone deletes the config dir while running).
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create config directory: {e}"))?;
        }

        // Write to a uniquely-named sibling temp file, fsync, then rename for
        // crash safety. Without fsync, a power loss between write and rename could
        // leave the temp file empty/truncated, and rename would replace the good
        // config with a corrupt one.
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp_path = config_path.with_extension(format!("toml.{n}.tmp"));

        let file = std::fs::File::create(&tmp_path)
            .map_err(|e| format!("failed to create temp config: {e}"))?;
        use std::io::Write;
        let mut writer = std::io::BufWriter::new(file);
        writer
            .write_all(toml_str.as_bytes())
            .map_err(|e| format!("failed to write temp config: {e}"))?;
        writer
            .flush()
            .map_err(|e| format!("failed to flush temp config: {e}"))?;
        writer
            .into_inner()
            .map_err(|e| format!("failed to finalize temp config: {e}"))?
            .sync_all()
            .map_err(|e| format!("failed to sync temp config to disk: {e}"))?;

        std::fs::rename(&tmp_path, &config_path)
            .map_err(|e| format!("failed to atomically replace config: {e}"))?;

        Ok(())
    }

    /// Save current state to disk.
    fn save_state(&self) {
        let mut daemon_state = DaemonState::new(std::process::id());
        daemon_state.started_at = chrono::Utc::now()
            - chrono::Duration::seconds(self.started_at.elapsed().as_secs() as i64);

        for name in self.fleet.agent_names() {
            if let Some(slot) = self.fleet.slot(&name) {
                let sid = *slot
                    .session_id
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                daemon_state.agents.push(state::AgentState {
                    name: name.clone(),
                    was_running: slot.is_thread_alive(),
                    session_id: sid,
                    restart_count: slot.restart_count,
                });
            }
        }

        if let Err(e) = daemon_state.save() {
            tracing::warn!(error = %e, "failed to save daemon state, retrying");
            std::thread::sleep(std::time::Duration::from_millis(100));
            if let Err(e2) = daemon_state.save() {
                tracing::error!(error = %e2, "state save failed twice, persistence may be broken");
            }
        }
    }
}

/// Map a Claude Code tool use into an Aegis `ActionKind` for Cedar policy evaluation.
///
/// Claude Code hooks provide `tool_name` (e.g., "Bash", "Read", "Write") and
/// `tool_input` (JSON with tool-specific parameters). We map these to the
/// corresponding `ActionKind` so Cedar policies can make fine-grained decisions
/// about file paths, commands, URLs, etc.
fn map_tool_use_to_action(tool_name: &str, tool_input: &serde_json::Value) -> ActionKind {
    match tool_name {
        "Bash" => {
            let command = tool_input
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            ActionKind::ProcessSpawn {
                command,
                args: vec![],
            }
        }
        "Read" | "NotebookRead" => {
            let path = tool_input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .into();
            ActionKind::FileRead { path }
        }
        "Write" => {
            let path = tool_input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .into();
            ActionKind::FileWrite { path }
        }
        "Edit" => {
            let path = tool_input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .into();
            ActionKind::FileWrite { path }
        }
        "NotebookEdit" => {
            let path = tool_input
                .get("notebook_path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .into();
            ActionKind::FileWrite { path }
        }
        "Glob" | "Grep" | "LS" => {
            let path = tool_input
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or(".")
                .into();
            ActionKind::DirList { path }
        }
        "WebFetch" => {
            let url = tool_input
                .get("url")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            ActionKind::NetRequest {
                method: "GET".to_string(),
                url,
            }
        }
        "WebSearch" => {
            let query = tool_input
                .get("query")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            ActionKind::NetRequest {
                method: "GET".to_string(),
                url: query,
            }
        }
        _ => ActionKind::ToolCall {
            tool: tool_name.to_string(),
            args: tool_input.clone(),
        },
    }
}

/// Tools that require human interaction and would stall a headless agent.
///
/// Only `AskUserQuestion` is blocked -- it genuinely waits for human input
/// and would stall a headless agent indefinitely.
///
/// Plan mode tools (`EnterPlanMode`, `ExitPlanMode`) are intentionally allowed.
/// Plan mode produces better results by giving CC time to research and design
/// before implementing. With `--dangerously-skip-permissions`, `ExitPlanMode`
/// auto-approves so the agent flows through plan -> implement without stalling.
fn is_interactive_tool(tool_name: &str) -> bool {
    tool_name == "AskUserQuestion"
}

fn is_known_policy_tool(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "Bash"
            | "Read"
            | "NotebookRead"
            | "Write"
            | "Edit"
            | "NotebookEdit"
            | "Glob"
            | "Grep"
            | "LS"
            | "WebFetch"
            | "WebSearch"
            | "AskUserQuestion"
            | "EnterPlanMode"
            | "ExitPlanMode"
    )
}

/// Compose a denial reason that guides the model to proceed autonomously.
///
/// Includes the agent's role, goal, context, and task (if configured) so the
/// model has enough information to make decisions without human input. Also
/// includes the fleet-wide goal if set.
fn compose_autonomy_prompt(
    tool_name: &str,
    fleet_goal: Option<&str>,
    agent_config: Option<&AgentSlotConfig>,
) -> String {
    let mut sections = Vec::new();

    sections.push(format!(
        "You are running as an autonomous agent managed by Aegis. \
         {tool_name} is not available in headless mode -- proceed without it."
    ));

    if let Some(goal) = fleet_goal {
        if !goal.is_empty() {
            sections.push(format!("Fleet mission: {goal}"));
        }
    }

    if let Some(config) = agent_config {
        if let Some(ref role) = config.role {
            if !role.is_empty() {
                sections.push(format!("Your role: {role}"));
            }
        }
        if let Some(ref goal) = config.agent_goal {
            if !goal.is_empty() {
                sections.push(format!("Your goal: {goal}"));
            }
        }
        if let Some(ref ctx) = config.context {
            if !ctx.is_empty() {
                sections.push(format!("Context: {ctx}"));
            }
        }
        if let Some(ref task) = config.task {
            if !task.is_empty() {
                sections.push(format!("Your task: {task}"));
            }
        }
    }

    // Only AskUserQuestion is denied, so guidance is always about autonomous decisions.
    sections.push(
        "Make decisions autonomously based on your role and context. \
         Do not ask clarifying questions -- use your best judgment and proceed."
            .to_string(),
    );

    sections.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_control::daemon::{CaptureSessionRequest, LatestCaptureFrame};
    use aegis_pilot::supervisor::SupervisorCommand;
    use aegis_policy::builtin::{ORCHESTRATOR_COMPUTER_USE, PERMIT_ALL};
    use aegis_toolkit::contract::InputAction;
    use aegis_toolkit::contract::{MouseButton, ToolAction};
    use aegis_types::daemon::{
        AgentSlotConfig, AgentToolConfig, DaemonControlConfig, OrchestratorConfig,
        PersistenceConfig, RestartPolicy,
    };
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::time::Duration;
    use tempfile::TempDir;

    fn test_runtime(agents: Vec<AgentSlotConfig>) -> DaemonRuntime {
        let config = DaemonConfig {
            goal: None,
            persistence: PersistenceConfig::default(),
            control: DaemonControlConfig::default(),
            dashboard: Default::default(),
            alerts: vec![],
            agents,
            channel: None,
            toolkit: Default::default(),
            memory: Default::default(),
            cron: Default::default(),
            plugins: Default::default(),
            aliases: Default::default(),
        };
        let aegis_config = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));
        DaemonRuntime::new(config, aegis_config)
    }

    fn test_agent(name: &str) -> AgentSlotConfig {
        AgentSlotConfig {
            name: name.to_string(),
            tool: AgentToolConfig::ClaudeCode {
                skip_permissions: false,
                one_shot: false,
                extra_args: vec![],
            },
            working_dir: PathBuf::from("/tmp"),
            role: None,
            agent_goal: None,
            context: None,
            task: Some("test task".into()),
            pilot: None,
            restart: RestartPolicy::OnFailure,
            max_restarts: 5,
            enabled: true,
            orchestrator: None,
            security_preset: None,
            policy_dir: None,
            isolation: None,
        }
    }

    #[test]
    fn daemon_runtime_creation() {
        let runtime = test_runtime(vec![]);
        assert_eq!(runtime.fleet.agent_count(), 0);
        assert!(!runtime.shutdown.load(Ordering::Relaxed));
    }

    #[test]
    fn shutdown_flag() {
        let runtime = test_runtime(vec![]);
        let flag = runtime.shutdown_flag();
        assert!(!flag.load(Ordering::Relaxed));
        runtime.request_shutdown();
        assert!(flag.load(Ordering::Relaxed));
    }

    #[test]
    fn handle_command_ping() {
        let mut runtime = test_runtime(vec![test_agent("a1"), test_agent("a2")]);
        let resp = runtime.handle_command(DaemonCommand::Ping);
        assert!(resp.ok);
        let data = resp.data.unwrap();
        let ping: DaemonPing = serde_json::from_value(data).unwrap();
        assert_eq!(ping.agent_count, 2);
        assert_eq!(ping.running_count, 0);
        assert!(!ping.hook_fail_open);
    }

    #[test]
    fn handle_command_list_agents() {
        let mut runtime = test_runtime(vec![test_agent("beta"), test_agent("alpha")]);
        let resp = runtime.handle_command(DaemonCommand::ListAgents);
        assert!(resp.ok);
        let data = resp.data.unwrap();
        let agents: Vec<AgentSummary> = serde_json::from_value(data).unwrap();
        assert_eq!(agents.len(), 2);
        // Should be sorted alphabetically
        assert_eq!(agents[0].name, "alpha");
        assert_eq!(agents[1].name, "beta");
    }

    #[test]
    fn handle_command_agent_status_unknown() {
        let mut runtime = test_runtime(vec![]);
        let resp = runtime.handle_command(DaemonCommand::AgentStatus {
            name: "nonexistent".into(),
        });
        assert!(!resp.ok);
        assert!(resp.message.contains("unknown"));
    }

    #[test]
    fn handle_command_agent_status_known() {
        let mut runtime = test_runtime(vec![test_agent("claude-1")]);
        let resp = runtime.handle_command(DaemonCommand::AgentStatus {
            name: "claude-1".into(),
        });
        assert!(resp.ok);
        let data = resp.data.unwrap();
        let detail: AgentDetail = serde_json::from_value(data).unwrap();
        assert_eq!(detail.name, "claude-1");
        assert_eq!(detail.tool, "ClaudeCode");
        assert!(detail.enabled);
        assert_eq!(detail.task, Some("test task".into()));
    }

    #[test]
    fn handle_command_start_unknown() {
        let mut runtime = test_runtime(vec![]);
        let resp = runtime.handle_command(DaemonCommand::StartAgent {
            name: "nope".into(),
        });
        assert!(!resp.ok);
    }

    #[test]
    fn handle_command_stop_unknown() {
        let mut runtime = test_runtime(vec![]);
        let resp = runtime.handle_command(DaemonCommand::StopAgent {
            name: "nope".into(),
        });
        assert!(!resp.ok);
    }

    #[test]
    fn handle_command_shutdown() {
        let mut runtime = test_runtime(vec![]);
        let resp = runtime.handle_command(DaemonCommand::Shutdown);
        assert!(resp.ok);
        assert!(runtime.shutdown.load(Ordering::Relaxed));
    }

    #[test]
    fn handle_command_agent_output_unknown() {
        let mut runtime = test_runtime(vec![]);
        let resp = runtime.handle_command(DaemonCommand::AgentOutput {
            name: "nope".into(),
            lines: Some(10),
        });
        assert!(!resp.ok);
    }

    #[test]
    fn handle_command_agent_output_empty() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let resp = runtime.handle_command(DaemonCommand::AgentOutput {
            name: "a1".into(),
            lines: Some(10),
        });
        assert!(resp.ok);
        let data = resp.data.unwrap();
        let lines: Vec<String> = serde_json::from_value(data).unwrap();
        assert!(lines.is_empty());
    }

    #[test]
    fn handle_command_approve_unknown_agent() {
        let mut runtime = test_runtime(vec![]);
        let resp = runtime.handle_command(DaemonCommand::ApproveRequest {
            name: "ghost".into(),
            request_id: "550e8400-e29b-41d4-a716-446655440000".into(),
        });
        assert!(!resp.ok);
    }

    #[test]
    fn handle_command_approve_invalid_uuid() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let resp = runtime.handle_command(DaemonCommand::ApproveRequest {
            name: "a1".into(),
            request_id: "not-a-uuid".into(),
        });
        assert!(!resp.ok);
        assert!(resp.message.contains("invalid request_id"));
    }

    #[test]
    fn handle_command_deny_unknown_agent() {
        let mut runtime = test_runtime(vec![]);
        let resp = runtime.handle_command(DaemonCommand::DenyRequest {
            name: "ghost".into(),
            request_id: "550e8400-e29b-41d4-a716-446655440000".into(),
        });
        assert!(!resp.ok);
    }

    #[test]
    fn handle_command_nudge_unknown_agent() {
        let mut runtime = test_runtime(vec![]);
        let resp = runtime.handle_command(DaemonCommand::NudgeAgent {
            name: "ghost".into(),
            message: None,
        });
        assert!(!resp.ok);
    }

    #[test]
    fn handle_command_list_pending_empty() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let resp = runtime.handle_command(DaemonCommand::ListPending { name: "a1".into() });
        assert!(resp.ok);
        let data = resp.data.unwrap();
        let pending: Vec<PendingPromptSummary> = serde_json::from_value(data).unwrap();
        assert!(pending.is_empty());
    }

    #[test]
    fn handle_command_list_pending_unknown() {
        let mut runtime = test_runtime(vec![]);
        let resp = runtime.handle_command(DaemonCommand::ListPending {
            name: "ghost".into(),
        });
        assert!(!resp.ok);
    }

    #[test]
    fn handle_command_evaluate_tool_use_no_policy() {
        let mut runtime = test_runtime(vec![]);
        let resp = runtime.handle_command(DaemonCommand::EvaluateToolUse {
            agent: "claude-1".into(),
            tool_name: "Bash".into(),
            tool_input: serde_json::json!({"command": "ls -la"}),
        });
        assert!(resp.ok);
        let data = resp.data.unwrap();
        let verdict: ToolUseVerdict = serde_json::from_value(data).unwrap();
        assert_eq!(verdict.decision, "deny");
        assert!(verdict.reason.contains("fail-closed"));
    }

    #[test]
    fn handle_command_runtime_capabilities() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let resp = runtime.handle_command(DaemonCommand::RuntimeCapabilities { name: "a1".into() });
        assert!(resp.ok);
        let caps: RuntimeCapabilities = serde_json::from_value(resp.data.unwrap()).unwrap();
        assert_eq!(caps.name, "a1");
        assert_eq!(caps.tool, "ClaudeCode");
        assert_eq!(caps.policy_mediation, "enforced");
        assert!(caps.headless);
        assert!(!caps.auth_mode.is_empty());
        assert!(!caps.auth_hint.is_empty());
    }

    #[test]
    fn handle_command_execute_tool_action_fail_closed() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let resp = runtime.handle_command(DaemonCommand::ExecuteToolAction {
            name: "a1".into(),
            action: ToolAction::MouseClick {
                x: 100,
                y: 200,
                button: MouseButton::Left,
            },
        });
        assert!(resp.ok);
        let data = resp.data.unwrap();
        let outcome: ToolActionOutcome = serde_json::from_value(data).unwrap();
        assert_eq!(outcome.execution.result.action, "MouseClick");
        assert_eq!(
            outcome.execution.risk_tag,
            outcome.execution.result.risk_tag
        );
        let note = outcome.execution.result.note.unwrap_or_default();
        assert!(note.contains("deny"));
    }

    #[test]
    fn handle_command_execute_tool_batch_halts_on_high_risk_boundary() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let resp = runtime.handle_command(DaemonCommand::ExecuteToolBatch {
            name: "a1".into(),
            actions: vec![
                ToolAction::MouseMove { x: 10, y: 20 },
                ToolAction::BrowserNavigate {
                    session_id: "b1".into(),
                    url: "https://example.com".into(),
                },
            ],
            max_actions: Some(5),
        });
        assert!(resp.ok);
        let batch: ToolBatchOutcome = serde_json::from_value(resp.data.unwrap()).unwrap();
        assert_eq!(batch.executed, 1);
        let halted = batch.halted_reason.unwrap_or_default();
        assert!(!halted.is_empty(), "batch should report a halt reason");
        assert!(
            halted.contains("policy boundary")
                || halted.contains("denied action")
                || halted.contains("batch cap"),
            "unexpected halt reason: {halted}"
        );
    }

    #[test]
    fn handle_command_start_capture_session_fail_closed_without_policy() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let resp = runtime.handle_command(DaemonCommand::StartCaptureSession {
            name: "a1".into(),
            request: aegis_control::daemon::CaptureSessionRequest {
                target_fps: 30,
                region: None,
            },
        });
        assert!(!resp.ok);
        assert!(resp.message.contains("denied"));
    }

    #[test]
    fn handle_command_stop_capture_session_fail_closed_without_policy() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let resp = runtime.handle_command(DaemonCommand::StopCaptureSession {
            name: "a1".into(),
            session_id: "cap-1".into(),
        });
        assert!(!resp.ok);
        assert!(resp.message.contains("denied"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires local browser + macOS permissions (screen recording/accessibility)"]
    fn live_browser_automation_writes_runtime_provenance() {
        if std::env::var("AEGIS_LIVE_AUTOMATION_TEST").ok().as_deref() != Some("1") {
            eprintln!("set AEGIS_LIVE_AUTOMATION_TEST=1 to run live automation integration test");
            return;
        }

        let tmp = TempDir::new().expect("create temp dir");
        let base = tmp.path().join("live-automation");
        let policy_dir = base.join("policies");
        std::fs::create_dir_all(&policy_dir).expect("create policy dir");
        std::fs::write(policy_dir.join("default.cedar"), ORCHESTRATOR_COMPUTER_USE)
            .expect("write policy");

        let mut config = DaemonConfig {
            goal: None,
            persistence: PersistenceConfig::default(),
            control: DaemonControlConfig::default(),
            dashboard: Default::default(),
            alerts: vec![],
            agents: vec![test_agent("orch")],
            channel: None,
            toolkit: Default::default(),
            memory: Default::default(),
            cron: Default::default(),
            plugins: Default::default(),
            aliases: Default::default(),
        };
        config.toolkit.loop_executor.halt_on_high_risk = false;
        config.toolkit.browser.extra_args = vec!["--disable-extensions".to_string()];

        let aegis_config = AegisConfig::default_for("live-orch", &base);
        let mut runtime = DaemonRuntime::new(config, aegis_config.clone());

        let start_capture = runtime.handle_command(DaemonCommand::StartCaptureSession {
            name: "orch".to_string(),
            request: CaptureSessionRequest {
                target_fps: 30,
                region: None,
            },
        });
        assert!(
            start_capture.ok,
            "capture start failed: {}",
            start_capture.message
        );
        let capture_started: CaptureSessionStarted = serde_json::from_value(
            start_capture
                .data
                .expect("capture start response should include session payload"),
        )
        .expect("parse capture session response");

        let start_browser = runtime.handle_command(DaemonCommand::ExecuteToolAction {
            name: "orch".to_string(),
            action: ToolAction::BrowserProfileStart {
                session_id: "live-web".to_string(),
                headless: true,
                url: Some("https://example.com".to_string()),
            },
        });
        assert!(
            start_browser.ok,
            "browser start failed: {}",
            start_browser.message
        );

        let mut first_frame: Option<LatestCaptureFrame> = None;
        for _ in 0..20 {
            let latest = runtime.handle_command(DaemonCommand::LatestCaptureFrame {
                name: "orch".to_string(),
                region: None,
            });
            if latest.ok {
                let payload: LatestCaptureFrame =
                    serde_json::from_value(latest.data.expect("latest frame payload"))
                        .expect("parse latest frame");
                if payload.frame_id > 0 && payload.frame.width > 0 && payload.frame.height > 0 {
                    first_frame = Some(payload);
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let first_frame = first_frame.expect("initial latest-frame should be available");

        let batch = runtime.handle_command(DaemonCommand::ExecuteToolBatch {
            name: "orch".to_string(),
            actions: vec![
                ToolAction::BrowserNavigate {
                    session_id: "live-web".to_string(),
                    url: "https://example.com".to_string(),
                },
                ToolAction::MouseClick {
                    x: 20,
                    y: 20,
                    button: MouseButton::Left,
                },
                ToolAction::TypeText {
                    text: "aegis live test".to_string(),
                },
                ToolAction::InputBatch {
                    actions: vec![InputAction::Wait { duration_ms: 150 }],
                },
            ],
            max_actions: Some(6),
        });
        assert!(batch.ok, "batch failed: {}", batch.message);
        let batch_outcome: ToolBatchOutcome =
            serde_json::from_value(batch.data.expect("batch data")).expect("parse batch outcome");
        assert_eq!(
            batch_outcome.executed, 4,
            "all batch actions should execute"
        );

        let mut advanced_frame: Option<LatestCaptureFrame> = None;
        for _ in 0..25 {
            let latest = runtime.handle_command(DaemonCommand::LatestCaptureFrame {
                name: "orch".to_string(),
                region: None,
            });
            if latest.ok {
                let payload: LatestCaptureFrame =
                    serde_json::from_value(latest.data.expect("latest frame payload"))
                        .expect("parse latest frame");
                if payload.frame_id > first_frame.frame_id
                    && payload.frame.width > 0
                    && payload.frame.height > 0
                {
                    advanced_frame = Some(payload);
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let advanced_frame =
            advanced_frame.expect("latest-frame should advance after action batch");
        assert!(advanced_frame.frame_id > first_frame.frame_id);

        let stop_browser = runtime.handle_command(DaemonCommand::StopBrowserProfile {
            name: "orch".to_string(),
            session_id: "live-web".to_string(),
        });
        assert!(
            stop_browser.ok,
            "browser stop failed: {}",
            stop_browser.message
        );

        let stop_capture = runtime.handle_command(DaemonCommand::StopCaptureSession {
            name: "orch".to_string(),
            session_id: capture_started.session_id,
        });
        assert!(
            stop_capture.ok,
            "capture stop failed: {}",
            stop_capture.message
        );

        let store = AuditStore::open(&aegis_config.ledger_path).expect("open audit ledger");
        let entries = store.query_last(200).expect("query audit entries");
        assert!(
            entries
                .iter()
                .any(|e| e.action_kind.contains("RuntimeComputerUse")),
            "expected RuntimeComputerUse audit entries"
        );
        assert!(
            entries
                .iter()
                .any(|e| e.action_kind.contains("BrowserProfileStart")),
            "expected BrowserProfileStart provenance in audit entries"
        );
        assert!(
            entries
                .iter()
                .any(|e| e.action_kind.contains("BrowserProfileStop")),
            "expected BrowserProfileStop provenance in audit entries"
        );
        assert!(
            entries
                .iter()
                .any(|e| e.action_kind.contains("BrowserNavigate")),
            "expected BrowserNavigate provenance in audit entries"
        );
        assert!(
            entries.iter().any(|e| e.action_kind.contains("MouseClick")),
            "expected MouseClick provenance in audit entries"
        );
        assert!(
            entries.iter().any(|e| e.action_kind.contains("TypeText")),
            "expected TypeText provenance in audit entries"
        );
        assert!(
            entries
                .iter()
                .any(|e| e.action_kind.contains("duration_ms")),
            "expected wait action provenance in audit entries"
        );
    }

    #[test]
    fn map_tool_use_bash() {
        let kind = map_tool_use_to_action("Bash", &serde_json::json!({"command": "ls -la"}));
        match kind {
            ActionKind::ProcessSpawn { command, .. } => assert_eq!(command, "ls -la"),
            other => panic!("expected ProcessSpawn, got {other:?}"),
        }
    }

    #[test]
    fn map_tool_use_read() {
        let kind = map_tool_use_to_action("Read", &serde_json::json!({"file_path": "/tmp/f.txt"}));
        match kind {
            ActionKind::FileRead { path } => assert_eq!(path, PathBuf::from("/tmp/f.txt")),
            other => panic!("expected FileRead, got {other:?}"),
        }
    }

    #[test]
    fn map_tool_use_write() {
        let kind =
            map_tool_use_to_action("Write", &serde_json::json!({"file_path": "/tmp/out.txt"}));
        match kind {
            ActionKind::FileWrite { path } => assert_eq!(path, PathBuf::from("/tmp/out.txt")),
            other => panic!("expected FileWrite, got {other:?}"),
        }
    }

    #[test]
    fn map_tool_use_edit() {
        let kind =
            map_tool_use_to_action("Edit", &serde_json::json!({"file_path": "/src/main.rs"}));
        match kind {
            ActionKind::FileWrite { path } => assert_eq!(path, PathBuf::from("/src/main.rs")),
            other => panic!("expected FileWrite, got {other:?}"),
        }
    }

    #[test]
    fn map_tool_use_glob() {
        let kind = map_tool_use_to_action("Glob", &serde_json::json!({"path": "/src"}));
        match kind {
            ActionKind::DirList { path } => assert_eq!(path, PathBuf::from("/src")),
            other => panic!("expected DirList, got {other:?}"),
        }
    }

    #[test]
    fn map_tool_use_web_fetch() {
        let kind = map_tool_use_to_action(
            "WebFetch",
            &serde_json::json!({"url": "https://example.com"}),
        );
        match kind {
            ActionKind::NetRequest { url, .. } => assert_eq!(url, "https://example.com"),
            other => panic!("expected NetRequest, got {other:?}"),
        }
    }

    #[test]
    fn map_tool_use_unknown_falls_back_to_tool_call() {
        let input = serde_json::json!({"foo": "bar"});
        let kind = map_tool_use_to_action("CustomTool", &input);
        match kind {
            ActionKind::ToolCall { tool, args } => {
                assert_eq!(tool, "CustomTool");
                assert_eq!(args, input);
            }
            other => panic!("expected ToolCall, got {other:?}"),
        }
    }

    // ── Interactive tool interception tests ───────────────────────────

    #[test]
    fn is_interactive_tool_only_blocks_ask_user() {
        assert!(is_interactive_tool("AskUserQuestion"));
        // Plan mode tools are allowed -- plan mode produces better results
        // and auto-approves with --dangerously-skip-permissions.
        assert!(!is_interactive_tool("EnterPlanMode"));
        assert!(!is_interactive_tool("ExitPlanMode"));
        assert!(!is_interactive_tool("Bash"));
        assert!(!is_interactive_tool("Read"));
        assert!(!is_interactive_tool("Write"));
    }

    #[test]
    fn compose_autonomy_prompt_minimal() {
        let prompt = compose_autonomy_prompt("AskUserQuestion", None, None);
        assert!(prompt.contains("autonomous agent"));
        assert!(prompt.contains("AskUserQuestion"));
        assert!(prompt.contains("best judgment"));
    }

    #[test]
    fn compose_autonomy_prompt_with_context() {
        let config = AgentSlotConfig {
            name: "ux-agent".into(),
            tool: AgentToolConfig::ClaudeCode {
                skip_permissions: false,
                one_shot: false,
                extra_args: vec![],
            },
            working_dir: PathBuf::from("/tmp"),
            role: Some("UX specialist".into()),
            agent_goal: Some("Build the homepage".into()),
            context: Some("React + TypeScript stack".into()),
            task: Some("Create a responsive nav bar".into()),
            pilot: None,
            restart: RestartPolicy::OnFailure,
            max_restarts: 5,
            enabled: true,
            orchestrator: None,
            security_preset: None,
            policy_dir: None,
            isolation: None,
        };

        let prompt = compose_autonomy_prompt(
            "AskUserQuestion",
            Some("Build a production chess app"),
            Some(&config),
        );

        assert!(prompt.contains("Fleet mission: Build a production chess app"));
        assert!(prompt.contains("Your role: UX specialist"));
        assert!(prompt.contains("Your goal: Build the homepage"));
        assert!(prompt.contains("Context: React + TypeScript"));
        assert!(prompt.contains("Your task: Create a responsive nav bar"));
        assert!(prompt.contains("best judgment"));
    }

    #[test]
    fn compose_autonomy_prompt_always_includes_judgment_guidance() {
        // All denied tools (only AskUserQuestion) get the same guidance.
        let prompt = compose_autonomy_prompt("AskUserQuestion", None, None);
        assert!(prompt.contains("best judgment"));
        assert!(prompt.contains("autonomous"));
    }

    #[test]
    fn evaluate_tool_use_denies_interactive_tools() {
        let agent = test_agent("agent-1");
        let mut runtime = test_runtime(vec![agent]);
        let resp = runtime.handle_command(DaemonCommand::EvaluateToolUse {
            agent: "agent-1".into(),
            tool_name: "AskUserQuestion".into(),
            tool_input: serde_json::json!({"question": "what approach?"}),
        });
        assert!(resp.ok);
        let verdict: ToolUseVerdict = serde_json::from_value(resp.data.unwrap()).unwrap();
        assert_eq!(verdict.decision, "deny");
        assert!(verdict.reason.contains("autonomous"));
    }

    #[test]
    fn evaluate_tool_use_denies_when_policy_unavailable() {
        let mut runtime = test_runtime(vec![test_agent("agent-1")]);
        let resp = runtime.handle_command(DaemonCommand::EvaluateToolUse {
            agent: "agent-1".into(),
            tool_name: "Read".into(),
            tool_input: serde_json::json!({"file_path": "/tmp/test.txt"}),
        });
        assert!(resp.ok);
        let verdict: ToolUseVerdict = serde_json::from_value(resp.data.unwrap()).unwrap();
        assert_eq!(verdict.decision, "deny");
        assert!(verdict.reason.contains("fail-closed"));
    }

    #[test]
    fn handle_command_reload_config_without_file() {
        // ReloadConfig should fail gracefully if daemon.toml doesn't exist
        // at the standard path. We can't easily test a full reload since
        // daemon_config_path() is system-dependent, but we can verify
        // the command doesn't panic.
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let resp = runtime.handle_command(DaemonCommand::ReloadConfig);
        // May succeed or fail depending on whether daemon.toml exists on disk
        // The important thing is it doesn't panic
        let _ = resp;
    }

    #[test]
    fn handle_command_enable_agent() {
        let mut config = test_agent("a1");
        config.enabled = false;
        let mut runtime = test_runtime(vec![config]);
        let resp = runtime.handle_command(DaemonCommand::EnableAgent { name: "a1".into() });
        assert!(resp.ok);
        assert!(resp.message.contains("enabled"));
    }

    #[test]
    fn handle_command_disable_agent() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let resp = runtime.handle_command(DaemonCommand::DisableAgent { name: "a1".into() });
        assert!(resp.ok);
        assert!(resp.message.contains("disabled"));
    }

    #[test]
    fn handle_command_enable_unknown_agent() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let resp = runtime.handle_command(DaemonCommand::EnableAgent {
            name: "ghost".into(),
        });
        assert!(!resp.ok);
    }

    #[test]
    fn handle_command_remove_agent() {
        let mut runtime = test_runtime(vec![test_agent("a1"), test_agent("a2")]);
        assert_eq!(runtime.fleet.agent_count(), 2);
        let resp = runtime.handle_command(DaemonCommand::RemoveAgent { name: "a1".into() });
        assert!(resp.ok);
        assert_eq!(runtime.fleet.agent_count(), 1);
        assert!(runtime.fleet.agent_status("a1").is_none());
        assert!(runtime.fleet.agent_status("a2").is_some());
        // Config should also be updated
        assert_eq!(runtime.config.agents.len(), 1);
        assert_eq!(runtime.config.agents[0].name, "a2");
    }

    #[test]
    fn handle_command_remove_unknown_agent() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let resp = runtime.handle_command(DaemonCommand::RemoveAgent {
            name: "ghost".into(),
        });
        assert!(!resp.ok);
        assert_eq!(runtime.fleet.agent_count(), 1);
    }

    #[test]
    fn handle_command_update_agent_context() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);

        let resp = runtime.handle_command(DaemonCommand::UpdateAgentContext {
            name: "a1".into(),
            role: Some("UX specialist".into()),
            agent_goal: Some("Design the landing page".into()),
            context: Some("Use Tailwind CSS".into()),
            task: None, // leave unchanged
        });
        assert!(resp.ok, "update should succeed: {}", resp.message);

        let slot = runtime.fleet.slot("a1").unwrap();
        assert_eq!(slot.config.role.as_deref(), Some("UX specialist"));
        assert_eq!(
            slot.config.agent_goal.as_deref(),
            Some("Design the landing page")
        );
        assert_eq!(slot.config.context.as_deref(), Some("Use Tailwind CSS"));
        assert_eq!(
            slot.config.task.as_deref(),
            Some("test task"),
            "task should be unchanged"
        );
    }

    #[test]
    fn handle_command_update_context_clear_field() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);

        // Set a role first
        runtime.handle_command(DaemonCommand::UpdateAgentContext {
            name: "a1".into(),
            role: Some("Backend dev".into()),
            agent_goal: None,
            context: None,
            task: None,
        });
        assert_eq!(
            runtime.fleet.slot("a1").unwrap().config.role.as_deref(),
            Some("Backend dev")
        );

        // Clear it with empty string
        let resp = runtime.handle_command(DaemonCommand::UpdateAgentContext {
            name: "a1".into(),
            role: Some("".into()),
            agent_goal: None,
            context: None,
            task: None,
        });
        assert!(resp.ok);
        assert!(
            runtime.fleet.slot("a1").unwrap().config.role.is_none(),
            "empty string should clear field"
        );
    }

    #[test]
    fn handle_command_update_context_unknown_agent() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let resp = runtime.handle_command(DaemonCommand::UpdateAgentContext {
            name: "ghost".into(),
            role: Some("whatever".into()),
            agent_goal: None,
            context: None,
            task: None,
        });
        assert!(!resp.ok);
    }

    #[test]
    fn handle_command_get_agent_context() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);

        // Set some context
        runtime.handle_command(DaemonCommand::UpdateAgentContext {
            name: "a1".into(),
            role: Some("Frontend dev".into()),
            agent_goal: Some("Build the dashboard".into()),
            context: None,
            task: None,
        });

        let resp = runtime.handle_command(DaemonCommand::GetAgentContext { name: "a1".into() });
        assert!(resp.ok);
        let data = resp.data.unwrap();
        assert_eq!(data["role"].as_str(), Some("Frontend dev"));
        assert_eq!(data["agent_goal"].as_str(), Some("Build the dashboard"));
        assert!(data["context"].is_null());
        assert_eq!(data["task"].as_str(), Some("test task"));
    }

    #[test]
    fn handle_command_get_context_unknown_agent() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let resp = runtime.handle_command(DaemonCommand::GetAgentContext {
            name: "ghost".into(),
        });
        assert!(!resp.ok);
    }

    #[test]
    fn handle_command_fleet_goal_set_and_get() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);

        // Get when no goal set -- returns null, not "(none)"
        let resp = runtime.handle_command(DaemonCommand::FleetGoal { goal: None });
        assert!(resp.ok);
        let data = resp.data.unwrap();
        assert!(data["goal"].is_null(), "unset goal should be null");

        // Set a goal
        let resp = runtime.handle_command(DaemonCommand::FleetGoal {
            goal: Some("Build a chess app".into()),
        });
        assert!(resp.ok);
        assert!(resp.message.contains("Build a chess app"));

        // Get the goal back
        let resp = runtime.handle_command(DaemonCommand::FleetGoal { goal: None });
        assert!(resp.ok);
        let data = resp.data.unwrap();
        assert_eq!(data["goal"].as_str(), Some("Build a chess app"));
    }

    #[test]
    fn handle_command_fleet_goal_clear() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);

        // Set then clear
        runtime.handle_command(DaemonCommand::FleetGoal {
            goal: Some("Build something".into()),
        });
        let resp = runtime.handle_command(DaemonCommand::FleetGoal {
            goal: Some("".into()),
        });
        assert!(resp.ok);
        assert!(resp.message.contains("(cleared)"));

        // Verify it's cleared -- returns null
        let resp = runtime.handle_command(DaemonCommand::FleetGoal { goal: None });
        let data = resp.data.unwrap();
        assert!(data["goal"].is_null(), "cleared goal should be null");
    }

    #[test]
    fn handle_command_send_to_agent_not_running() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let resp = runtime.handle_command(DaemonCommand::SendToAgent {
            name: "a1".into(),
            text: "hello".into(),
        });
        assert!(!resp.ok, "send to non-running agent should fail");
    }

    #[test]
    fn handle_command_send_to_unknown_agent() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let resp = runtime.handle_command(DaemonCommand::SendToAgent {
            name: "ghost".into(),
            text: "hello".into(),
        });
        assert!(!resp.ok);
    }

    #[test]
    fn handle_command_add_agent() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        assert_eq!(runtime.fleet.agent_count(), 1);

        let new_agent = test_agent("a2");
        let resp = runtime.handle_command(DaemonCommand::AddAgent {
            config: Box::new(new_agent),
            start: false,
        });
        assert!(resp.ok, "add should succeed: {}", resp.message);
        assert_eq!(runtime.fleet.agent_count(), 2);
        assert!(runtime.fleet.agent_status("a2").is_some());
    }

    #[test]
    fn handle_command_add_duplicate_agent() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let dup = test_agent("a1");
        let resp = runtime.handle_command(DaemonCommand::AddAgent {
            config: Box::new(dup),
            start: false,
        });
        assert!(!resp.ok, "duplicate should fail");
        assert!(resp.message.contains("already exists"));
    }

    #[test]
    fn handle_command_spawn_subagent_requires_orchestrator_or_subagent_parent() {
        let mut runtime = test_runtime(vec![test_agent("worker-1")]);
        runtime.policy_engine =
            Some(aegis_policy::PolicyEngine::from_policies(PERMIT_ALL, None).unwrap());
        let resp = runtime.handle_command(DaemonCommand::SpawnSubagent {
            request: SpawnSubagentRequest {
                parent: "worker-1".into(),
                name: Some("worker-sub-1".into()),
                role: None,
                task: None,
                depth_limit: Some(3),
                start: false,
            },
        });
        assert!(!resp.ok);
        assert!(resp.message.contains("not an orchestrator/subagent"));
    }

    #[test]
    fn handle_command_spawn_subagent_enforces_depth_limit() {
        let mut orch = test_agent("orchestrator");
        orch.orchestrator = Some(OrchestratorConfig::default());
        let mut runtime = test_runtime(vec![orch]);
        runtime.policy_engine =
            Some(aegis_policy::PolicyEngine::from_policies(PERMIT_ALL, None).unwrap());

        let first = runtime.handle_command(DaemonCommand::SpawnSubagent {
            request: SpawnSubagentRequest {
                parent: "orchestrator".into(),
                name: Some("worker-sub-1".into()),
                role: None,
                task: Some("Implement parser".into()),
                depth_limit: Some(1),
                start: false,
            },
        });
        assert!(first.ok, "first spawn should succeed: {}", first.message);

        let second = runtime.handle_command(DaemonCommand::SpawnSubagent {
            request: SpawnSubagentRequest {
                parent: "worker-sub-1".into(),
                name: Some("worker-sub-2".into()),
                role: None,
                task: Some("Write tests".into()),
                depth_limit: Some(1),
                start: false,
            },
        });
        assert!(!second.ok);
        assert!(second.message.contains("exceeds depth_limit"));
    }

    #[test]
    fn relay_subagent_results_child_exit_sends_parent_message_and_audits() {
        let tmp = TempDir::new().expect("create temp dir");
        let base = tmp.path().join("relay-subagent-result-ok");
        std::fs::create_dir_all(&base).expect("create base dir");

        let mut orchestrator = test_agent("orchestrator");
        orchestrator.orchestrator = Some(OrchestratorConfig::default());
        orchestrator.working_dir = base.clone();
        let config = DaemonConfig {
            goal: None,
            persistence: PersistenceConfig::default(),
            control: DaemonControlConfig::default(),
            dashboard: Default::default(),
            alerts: vec![],
            agents: vec![orchestrator],
            channel: None,
            toolkit: Default::default(),
            memory: Default::default(),
            cron: Default::default(),
            plugins: Default::default(),
            aliases: Default::default(),
        };
        let aegis_config = AegisConfig::default_for("relay-subagent-result-ok", &base);
        let mut runtime = DaemonRuntime::new(config, aegis_config.clone());
        runtime.policy_engine =
            Some(aegis_policy::PolicyEngine::from_policies(PERMIT_ALL, None).unwrap());

        let spawn = runtime.spawn_subagent(SpawnSubagentRequest {
            parent: "orchestrator".into(),
            name: Some("worker-sub-1".into()),
            role: Some("Test worker".into()),
            task: Some("Produce a deterministic output".into()),
            depth_limit: Some(3),
            start: false,
        });
        assert!(spawn.is_ok(), "subagent spawn should succeed: {spawn:?}");

        let (cmd_tx, cmd_rx) = mpsc::channel();
        runtime.fleet.slot_mut("orchestrator").unwrap().command_tx = Some(cmd_tx);
        if let Some(slot) = runtime.fleet.slot("worker-sub-1") {
            if let Ok(mut output) = slot.recent_output.lock() {
                output.push_back("subagent completed task".to_string());
            }
        }

        runtime.relay_subagent_results(&[(
            "worker-sub-1".to_string(),
            NotableEvent::ChildExited { exit_code: 0 },
        )]);

        let cmd = cmd_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("parent should receive subagent result");
        let text = match cmd {
            SupervisorCommand::SendInput { text } => text,
            other => panic!("expected SendInput relay, got {other:?}"),
        };
        assert!(text.starts_with("AEGIS_SUBAGENT_RESULT "));
        let payload = text
            .strip_prefix("AEGIS_SUBAGENT_RESULT ")
            .expect("result marker prefix");
        let parsed: serde_json::Value = serde_json::from_str(payload).expect("parse result JSON");
        assert_eq!(parsed["event"].as_str(), Some("subagent_result"));
        assert_eq!(parsed["parent"].as_str(), Some("orchestrator"));
        assert_eq!(parsed["child"].as_str(), Some("worker-sub-1"));
        assert_eq!(parsed["exit_code"].as_i64(), Some(0));
        assert!(parsed["output_tail"]
            .as_array()
            .is_some_and(|v| !v.is_empty()));

        let store = AuditStore::open(&aegis_config.ledger_path).expect("open audit ledger");
        let entries = store.query_last(100).expect("query audit entries");
        let relay_entry = entries
            .iter()
            .rev()
            .find(|entry| entry.action_kind.contains("SubagentResultReturn"))
            .expect("expected SubagentResultReturn audit entry");
        assert_eq!(relay_entry.decision, "Allow");
        let kind: serde_json::Value =
            serde_json::from_str(&relay_entry.action_kind).expect("parse action kind");
        assert_eq!(
            kind["ToolCall"]["args"]["delivered"].as_bool(),
            Some(true),
            "relay audit should record delivered=true"
        );
    }

    #[test]
    fn relay_subagent_results_without_parent_channel_audits_delivery_failure() {
        let tmp = TempDir::new().expect("create temp dir");
        let base = tmp.path().join("relay-subagent-result-no-parent-channel");
        std::fs::create_dir_all(&base).expect("create base dir");

        let mut orchestrator = test_agent("orchestrator");
        orchestrator.orchestrator = Some(OrchestratorConfig::default());
        orchestrator.working_dir = base.clone();
        let config = DaemonConfig {
            goal: None,
            persistence: PersistenceConfig::default(),
            control: DaemonControlConfig::default(),
            dashboard: Default::default(),
            alerts: vec![],
            agents: vec![orchestrator],
            channel: None,
            toolkit: Default::default(),
            memory: Default::default(),
            cron: Default::default(),
            plugins: Default::default(),
            aliases: Default::default(),
        };
        let aegis_config =
            AegisConfig::default_for("relay-subagent-result-no-parent-channel", &base);
        let mut runtime = DaemonRuntime::new(config, aegis_config.clone());
        runtime.policy_engine =
            Some(aegis_policy::PolicyEngine::from_policies(PERMIT_ALL, None).unwrap());

        let spawn = runtime.spawn_subagent(SpawnSubagentRequest {
            parent: "orchestrator".into(),
            name: Some("worker-sub-2".into()),
            role: None,
            task: Some("Return quickly".into()),
            depth_limit: Some(3),
            start: false,
        });
        assert!(spawn.is_ok(), "subagent spawn should succeed: {spawn:?}");

        runtime.relay_subagent_results(&[(
            "worker-sub-2".to_string(),
            NotableEvent::ChildExited { exit_code: 17 },
        )]);

        let store = AuditStore::open(&aegis_config.ledger_path).expect("open audit ledger");
        let entries = store.query_last(100).expect("query audit entries");
        let relay_entry = entries
            .iter()
            .rev()
            .find(|entry| entry.action_kind.contains("SubagentResultReturn"))
            .expect("expected SubagentResultReturn audit entry");
        assert_eq!(relay_entry.decision, "Allow");
        let kind: serde_json::Value =
            serde_json::from_str(&relay_entry.action_kind).expect("parse action kind");
        assert_eq!(
            kind["ToolCall"]["args"]["delivered"].as_bool(),
            Some(false),
            "relay audit should record delivered=false"
        );
        assert!(
            kind["ToolCall"]["args"]["delivery_error"]
                .as_str()
                .is_some_and(|v| v.contains("no command channel")),
            "delivery error should explain parent channel failure"
        );
    }

    #[test]
    fn handle_command_remove_agent_success() {
        let mut runtime = test_runtime(vec![test_agent("a1"), test_agent("a2")]);
        assert_eq!(runtime.fleet.agent_count(), 2);

        let resp = runtime.handle_command(DaemonCommand::RemoveAgent { name: "a1".into() });
        assert!(resp.ok, "remove should succeed: {}", resp.message);
        assert_eq!(runtime.fleet.agent_count(), 1);
        assert!(runtime.fleet.agent_status("a1").is_none());
        assert!(runtime.fleet.agent_status("a2").is_some());
    }

    #[test]
    fn handle_command_orchestrator_context_all_agents() {
        let mut runtime = test_runtime(vec![test_agent("worker-1"), test_agent("worker-2")]);
        let resp = runtime.handle_command(DaemonCommand::OrchestratorContext {
            agents: vec![],
            output_lines: None,
        });
        assert!(resp.ok);
        let snapshot: OrchestratorSnapshot = serde_json::from_value(resp.data.unwrap()).unwrap();
        assert_eq!(snapshot.agents.len(), 2);
        // Sorted alphabetically
        assert_eq!(snapshot.agents[0].name, "worker-1");
        assert_eq!(snapshot.agents[1].name, "worker-2");
    }

    #[test]
    fn handle_command_orchestrator_context_filters_orchestrator() {
        use aegis_types::daemon::OrchestratorConfig;
        let mut orch = test_agent("orchestrator");
        orch.orchestrator = Some(OrchestratorConfig::default());
        let mut runtime = test_runtime(vec![orch, test_agent("worker-1")]);
        let resp = runtime.handle_command(DaemonCommand::OrchestratorContext {
            agents: vec![],
            output_lines: None,
        });
        assert!(resp.ok);
        let snapshot: OrchestratorSnapshot = serde_json::from_value(resp.data.unwrap()).unwrap();
        // Should only contain the worker, not the orchestrator
        assert_eq!(snapshot.agents.len(), 1);
        assert_eq!(snapshot.agents[0].name, "worker-1");
    }

    #[test]
    fn handle_command_orchestrator_context_specific_agents() {
        let mut runtime = test_runtime(vec![test_agent("a1"), test_agent("a2"), test_agent("a3")]);
        let resp = runtime.handle_command(DaemonCommand::OrchestratorContext {
            agents: vec!["a1".into(), "a3".into()],
            output_lines: Some(10),
        });
        assert!(resp.ok);
        let snapshot: OrchestratorSnapshot = serde_json::from_value(resp.data.unwrap()).unwrap();
        assert_eq!(snapshot.agents.len(), 2);
        assert_eq!(snapshot.agents[0].name, "a1");
        assert_eq!(snapshot.agents[1].name, "a3");
    }

    #[test]
    fn handle_command_restart_agent_not_running() {
        let mut runtime = test_runtime(vec![test_agent("a1")]);
        let resp = runtime.handle_command(DaemonCommand::RestartAgent { name: "a1".into() });
        // RestartAgent stops + starts; stop on a non-running agent is fine
        assert!(resp.ok);
    }

    #[test]
    fn handle_command_add_agent_invalid_working_dir() {
        let mut runtime = test_runtime(vec![]);
        let mut agent = test_agent("bad-dir");
        agent.working_dir = PathBuf::from("/nonexistent/path/that/does/not/exist");
        let resp = runtime.handle_command(DaemonCommand::AddAgent {
            config: Box::new(agent),
            start: false,
        });
        assert!(!resp.ok, "should reject invalid working_dir");
        assert!(
            resp.message.contains("not a directory") || resp.message.contains("does not exist")
        );
    }

    #[test]
    fn parity_status_report_from_dir_parses_matrix() {
        let tmp = TempDir::new().expect("tmpdir");
        let matrix = tmp.path().join("matrix");
        let reports = tmp.path().join("reports");
        std::fs::create_dir_all(&matrix).expect("create matrix dir");
        std::fs::create_dir_all(&reports).expect("create reports dir");

        std::fs::write(
            matrix.join("features.yaml"),
            r#"
version: 1
updated_at_utc: "2026-02-21T00:00:00Z"
features:
  - feature_id: runtime.hooks.before_tool_call
    aegis_status: complete
    risk_level: high
    required_controls:
      - policy_gate_all_privileged_actions
    owner: runtime
  - feature_id: browser.cdp.session_control
    aegis_status: partial
    risk_level: high
    required_controls:
      - missing_control
    owner: browser
"#,
        )
        .expect("write features");
        std::fs::write(
            matrix.join("security_controls.yaml"),
            r#"
controls:
  - control_id: policy_gate_all_privileged_actions
"#,
        )
        .expect("write controls");

        let report = parity_status_report_from_dir(tmp.path()).expect("status report");
        assert_eq!(report.total_features, 2);
        assert_eq!(report.complete_features, 1);
        assert_eq!(report.partial_features, 1);
        assert_eq!(report.high_risk_blockers, 1);
    }

    #[test]
    fn parity_verify_report_from_dir_fails_on_high_risk_partial() {
        let tmp = TempDir::new().expect("tmpdir");
        let matrix = tmp.path().join("matrix");
        std::fs::create_dir_all(&matrix).expect("create matrix dir");

        std::fs::write(
            matrix.join("features.yaml"),
            r#"
version: 1
updated_at_utc: "2026-02-21T00:00:00Z"
features:
  - feature_id: orchestrator.computer_use.fast_loop
    aegis_status: partial
    risk_level: high
    required_controls:
      - policy_gate_all_privileged_actions
    owner: runtime
"#,
        )
        .expect("write features");
        std::fs::write(
            matrix.join("security_controls.yaml"),
            r#"
controls:
  - control_id: policy_gate_all_privileged_actions
"#,
        )
        .expect("write controls");

        let verify = parity_verify_report_from_dir(tmp.path()).expect("verify report");
        assert!(!verify.ok);
        assert_eq!(verify.checked_features, 1);
        assert!(verify
            .violations
            .iter()
            .any(|v| v.starts_with("R_HIGH_RISK_COMPLETE|")));
        assert_eq!(verify.violations_struct.len(), verify.violations.len());
        assert!(verify
            .violations_struct
            .iter()
            .any(|v| v.rule_id == "R_HIGH_RISK_COMPLETE"));
    }

    #[test]
    fn parity_verify_report_from_dir_fails_complete_gate_rules() {
        let tmp = TempDir::new().expect("tmpdir");
        let matrix = tmp.path().join("matrix");
        std::fs::create_dir_all(&matrix).expect("create matrix dir");

        std::fs::write(
            matrix.join("features.yaml"),
            r#"
version: 1
updated_at_utc: "2026-02-21T00:00:00Z"
features:
  - feature_id: runtime.tools.exec
    aegis_status: complete
    risk_level: medium
    required_controls:
      - missing_control
    owner: runtime
"#,
        )
        .expect("write features");
        std::fs::write(
            matrix.join("security_controls.yaml"),
            r#"
controls:
  - control_id: policy_gate_all_privileged_actions
"#,
        )
        .expect("write controls");

        let verify = parity_verify_report_from_dir(tmp.path()).expect("verify report");
        assert!(!verify.ok);
        assert!(verify
            .violations
            .iter()
            .any(|v| v.starts_with("R_COMPLETE_CONTROLS|runtime.tools.exec|")));
        assert!(verify
            .violations
            .iter()
            .any(|v| v.starts_with("R_COMPLETE_TESTS|runtime.tools.exec|")));
        assert!(verify
            .violations
            .iter()
            .any(|v| v.starts_with("R_COMPLETE_EVIDENCE|runtime.tools.exec|")));
    }

    #[test]
    fn parity_verify_report_from_dir_fails_unknown_status_and_risk() {
        let tmp = TempDir::new().expect("tmpdir");
        let matrix = tmp.path().join("matrix");
        std::fs::create_dir_all(&matrix).expect("create matrix dir");

        std::fs::write(
            matrix.join("features.yaml"),
            r#"
version: 1
updated_at_utc: "2026-02-21T00:00:00Z"
features:
  - feature_id: runtime.tools.web_search
    aegis_status: done
    risk_level: severe
    required_controls:
      - policy_gate_all_privileged_actions
    owner: runtime
"#,
        )
        .expect("write features");
        std::fs::write(
            matrix.join("security_controls.yaml"),
            r#"
controls:
  - control_id: policy_gate_all_privileged_actions
"#,
        )
        .expect("write controls");

        let verify = parity_verify_report_from_dir(tmp.path()).expect("verify report");
        assert!(!verify.ok);
        assert!(verify
            .violations
            .iter()
            .any(|v| v.starts_with("R_STATUS_ENUM|runtime.tools.web_search|")));
        assert!(verify
            .violations
            .iter()
            .any(|v| v.starts_with("R_RISK_ENUM|runtime.tools.web_search|")));
    }

    #[test]
    fn parity_verify_report_from_dir_passes_strict_complete() {
        let tmp = TempDir::new().expect("tmpdir");
        let matrix = tmp.path().join("matrix");
        std::fs::create_dir_all(&matrix).expect("create matrix dir");

        std::fs::write(
            matrix.join("features.yaml"),
            r#"
version: 1
updated_at_utc: "2026-02-21T00:00:00Z"
features:
  - feature_id: orchestrator.computer_use.fast_loop
    aegis_status: complete
    risk_level: critical
    required_controls:
      - policy_gate_all_privileged_actions
    owner: runtime
    acceptance_tests:
      - "tool actions are policy-gated"
    evidence_paths:
      - "crates/aegis-daemon/src/lib.rs"
"#,
        )
        .expect("write features");
        std::fs::write(
            matrix.join("security_controls.yaml"),
            r#"
controls:
  - control_id: policy_gate_all_privileged_actions
"#,
        )
        .expect("write controls");

        let verify = parity_verify_report_from_dir(tmp.path()).expect("verify report");
        assert!(verify.ok, "violations: {:?}", verify.violations);
        assert!(verify.violations.is_empty());
        assert!(verify.violations_struct.is_empty());
    }

    #[test]
    fn parity_diff_report_from_dir_reads_latest_report() {
        let tmp = TempDir::new().expect("tmpdir");
        let matrix = tmp.path().join("matrix");
        let reports = tmp.path().join("reports");
        std::fs::create_dir_all(&matrix).expect("create matrix dir");
        std::fs::create_dir_all(&reports).expect("create reports dir");

        std::fs::write(
            matrix.join("features.yaml"),
            r#"
version: 1
updated_at_utc: "2026-02-21T00:00:00Z"
features:
  - feature_id: orchestrator.computer_use.fast_loop
    aegis_status: partial
    risk_level: high
    required_controls:
      - policy_gate_all_privileged_actions
    owner: runtime
"#,
        )
        .expect("write features");
        std::fs::write(
            matrix.join("security_controls.yaml"),
            r#"
controls:
  - control_id: policy_gate_all_privileged_actions
"#,
        )
        .expect("write controls");

        let report_path = reports.join("abc.md");
        std::fs::write(
            &report_path,
            r#"
# OpenClaw Sync Report
- new_processed_sha: deadbeef

## Changed Files
- M src/a.ts
- A src/b.ts
"#,
        )
        .expect("write report");

        let diff = parity_diff_report_from_dir(tmp.path()).expect("diff report");
        assert_eq!(diff.upstream_sha, "deadbeef");
        assert_eq!(diff.changed_files, 2);
        assert_eq!(diff.impacted_feature_ids.len(), 1);
    }
}
