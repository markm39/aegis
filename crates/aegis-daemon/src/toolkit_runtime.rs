//! Orchestrator computer-use runtime backed by aegis-toolkit.

use std::collections::HashMap;
use std::env;
use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

use aegis_control::daemon::{BrowserToolData, FramePayload, ToolActionExecution, TuiToolData};
use aegis_toolkit::capture::CaptureRequest;
use aegis_toolkit::contract::{MouseButton as ContractMouseButton, ToolAction, ToolResult};
use aegis_toolkit::input::{InputProvider, KeyPress, MouseButton, MouseClick, MouseMove, TypeText};
use aegis_toolkit::policy::map_tool_action;
use aegis_toolkit::window::{WindowProvider, WindowRef};
use aegis_toolkit::{CaptureFrame, ToolkitError};
use aegis_types::daemon::ToolkitConfig;

use tungstenite::stream::MaybeTlsStream;
use tungstenite::{connect, Message, WebSocket};
use url::Url;

#[derive(Debug, Clone, serde::Serialize)]
pub struct ToolkitOutput {
    pub execution: ToolActionExecution,
    pub frame: Option<FramePayload>,
    pub tui: Option<TuiToolData>,
    pub browser: Option<BrowserToolData>,
}

/// Result of a budget-enforced batch execution.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BatchResult {
    /// Completed action outputs.
    pub completed: Vec<ToolkitOutput>,
    /// Number of actions that were executed.
    pub executed_count: usize,
    /// Total actions requested.
    pub total_requested: usize,
    /// Reason the batch stopped (if stopped early).
    pub halt_reason: Option<BatchHaltReason>,
    /// Total wall time for the batch in milliseconds.
    pub elapsed_ms: u64,
}

/// Why a batch was halted before completing all actions.
#[derive(Debug, Clone, serde::Serialize)]
pub enum BatchHaltReason {
    /// Time budget exceeded.
    TimeBudgetExceeded { budget_ms: u64, elapsed_ms: u64 },
    /// Maximum micro-actions reached.
    MaxActionsReached { max: u8, executed: usize },
    /// A high-risk action was encountered and halt_on_high_risk is enabled.
    HighRiskHalt { action_name: String },
    /// An action failed.
    ActionFailed { action_name: String, error: String },
}

pub trait TuiRuntimeBridge {
    fn snapshot(&self, session_id: &str) -> Result<TuiToolData, String>;
    fn send_input(&self, session_id: &str, text: &str) -> Result<TuiToolData, String>;
}

pub struct ToolkitRuntime {
    config: ToolkitConfig,
    #[cfg(target_os = "macos")]
    helper: aegis_toolkit::macos_helper::MacosHelper,
    browser_sessions: HashMap<String, BrowserSession>,
    managed_browsers: HashMap<String, ManagedBrowser>,
}

impl ToolkitRuntime {
    pub fn new(config: &ToolkitConfig) -> Result<Self, String> {
        #[cfg(target_os = "macos")]
        {
            let helper = aegis_toolkit::macos_helper()
                .map_err(|e| format!("macos helper unavailable: {e}"))?;
            Ok(Self {
                config: config.clone(),
                helper,
                browser_sessions: HashMap::new(),
                managed_browsers: HashMap::new(),
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = config;
            Err("toolkit runtime only implemented on macOS".to_string())
        }
    }

    pub fn execute(&mut self, action: &ToolAction) -> Result<ToolkitOutput, String> {
        self.execute_with_tui_bridge(action, None)
    }

    pub fn execute_with_tui_bridge(
        &mut self,
        action: &ToolAction,
        tui_bridge: Option<&dyn TuiRuntimeBridge>,
    ) -> Result<ToolkitOutput, String> {
        let mapping = map_tool_action(action);
        let mut result = ToolResult {
            action: mapping.cedar_action.to_string(),
            risk_tag: mapping.risk_tag,
            capture_latency_ms: None,
            input_latency_ms: None,
            frame_id: None,
            window_id: None,
            session_id: None,
            note: None,
        };

        let mut frame_payload: Option<FramePayload> = None;
        let mut tui_payload: Option<TuiToolData> = None;
        let mut browser_payload: Option<BrowserToolData> = None;

        match action {
            ToolAction::ScreenCapture { region, target_fps } => {
                if !self.config.capture.enabled {
                    return Err("capture actions are disabled by daemon toolkit config".to_string());
                }
                let request = CaptureRequest {
                    target_fps: (*target_fps).into(),
                    region: region.as_ref().map(|r| aegis_toolkit::capture::Region {
                        x: r.x,
                        y: r.y,
                        width: r.width,
                        height: r.height,
                    }),
                };
                let started = Instant::now();
                let frame = self.capture(&request).map_err(|e| e.to_string())?;
                let elapsed = started.elapsed().as_millis() as u64;
                result.capture_latency_ms = Some(elapsed);
                result.frame_id = Some(frame.metadata.frame_id);
                frame_payload = Some(frame_to_payload(frame)?);
            }
            ToolAction::WindowFocus { app_id, window_id } => {
                if !self.config.input.enabled {
                    return Err("input actions are disabled by daemon toolkit config".to_string());
                }
                let started = Instant::now();
                self.focus(app_id, *window_id).map_err(|e| e.to_string())?;
                result.input_latency_ms = Some(started.elapsed().as_millis() as u64);
                result.window_id = *window_id;
            }
            ToolAction::MouseMove { x, y } => {
                if !self.config.input.enabled {
                    return Err("input actions are disabled by daemon toolkit config".to_string());
                }
                let started = Instant::now();
                self.move_mouse(*x, *y).map_err(|e| e.to_string())?;
                result.input_latency_ms = Some(started.elapsed().as_millis() as u64);
            }
            ToolAction::MouseClick { x, y, button } => {
                if !self.config.input.enabled {
                    return Err("input actions are disabled by daemon toolkit config".to_string());
                }
                let started = Instant::now();
                self.click_mouse(*x, *y, button.clone())
                    .map_err(|e| e.to_string())?;
                result.input_latency_ms = Some(started.elapsed().as_millis() as u64);
            }
            ToolAction::MouseDrag {
                from_x,
                from_y,
                to_x,
                to_y,
            } => {
                if !self.config.input.enabled {
                    return Err("input actions are disabled by daemon toolkit config".to_string());
                }
                let started = Instant::now();
                self.drag_mouse(*from_x, *from_y, *to_x, *to_y)
                    .map_err(|e| e.to_string())?;
                result.input_latency_ms = Some(started.elapsed().as_millis() as u64);
            }
            ToolAction::KeyPress { keys } => {
                if !self.config.input.enabled {
                    return Err("input actions are disabled by daemon toolkit config".to_string());
                }
                let started = Instant::now();
                for key in keys {
                    self.key_press(key).map_err(|e| e.to_string())?;
                }
                result.input_latency_ms = Some(started.elapsed().as_millis() as u64);
            }
            ToolAction::TypeText { text } => {
                if !self.config.input.enabled {
                    return Err("input actions are disabled by daemon toolkit config".to_string());
                }
                let started = Instant::now();
                self.type_text(text).map_err(|e| e.to_string())?;
                result.input_latency_ms = Some(started.elapsed().as_millis() as u64);
            }
            ToolAction::TuiSnapshot { session_id } => {
                let bridge =
                    tui_bridge.ok_or_else(|| "tui runtime bridge unavailable".to_string())?;
                let started = Instant::now();
                let tui_data = bridge.snapshot(session_id)?;
                result.capture_latency_ms = Some(started.elapsed().as_millis() as u64);
                result.session_id = Some(tui_target(&tui_data).to_string());
                tui_payload = Some(tui_data);
            }
            ToolAction::TuiInput { session_id, text } => {
                let bridge =
                    tui_bridge.ok_or_else(|| "tui runtime bridge unavailable".to_string())?;
                let started = Instant::now();
                let tui_data = bridge.send_input(session_id, text)?;
                result.input_latency_ms = Some(started.elapsed().as_millis() as u64);
                result.session_id = Some(tui_target(&tui_data).to_string());
                tui_payload = Some(tui_data);
            }
            ToolAction::BrowserNavigate { session_id, url } => {
                if !self.config.browser.enabled {
                    return Err("browser actions are disabled by daemon toolkit config".to_string());
                }
                if !self
                    .config
                    .browser
                    .backend
                    .trim()
                    .eq_ignore_ascii_case("cdp")
                {
                    return Err(format!(
                        "unsupported browser backend '{}' (expected 'cdp')",
                        self.config.browser.backend
                    ));
                }
                let started = Instant::now();
                let res = self.with_browser_session(session_id, |session| {
                    session.client.call("Page.enable", serde_json::json!({}))?;
                    session
                        .client
                        .call("Page.navigate", serde_json::json!({ "url": url }))?;
                    Ok(())
                });
                if let Err(e) = res {
                    self.browser_sessions.remove(session_id);
                    return Err(e);
                }
                result.input_latency_ms = Some(started.elapsed().as_millis() as u64);
                let ws_url = self
                    .browser_sessions
                    .get(session_id)
                    .map(|s| s.endpoint.clone());
                browser_payload = Some(BrowserToolData {
                    session_id: session_id.clone(),
                    backend: "cdp".to_string(),
                    available: true,
                    note: "navigated".to_string(),
                    screenshot_base64: None,
                    ws_url,
                    result_json: None,
                });
            }
            ToolAction::BrowserEvaluate {
                session_id,
                expression,
                return_by_value,
            } => {
                if !self.config.browser.enabled {
                    return Err("browser actions are disabled by daemon toolkit config".to_string());
                }
                if !self
                    .config
                    .browser
                    .backend
                    .trim()
                    .eq_ignore_ascii_case("cdp")
                {
                    return Err(format!(
                        "unsupported browser backend '{}' (expected 'cdp')",
                        self.config.browser.backend
                    ));
                }
                let started = Instant::now();
                let mut eval_result = None;
                let res = self.with_browser_session(session_id, |session| {
                    session
                        .client
                        .call("Runtime.enable", serde_json::json!({}))?;
                    let result = session.client.call(
                        "Runtime.evaluate",
                        serde_json::json!({
                            "expression": expression,
                            "returnByValue": return_by_value,
                            "awaitPromise": true
                        }),
                    )?;
                    eval_result = Some(result);
                    Ok(())
                });
                if let Err(e) = res {
                    self.browser_sessions.remove(session_id);
                    return Err(e);
                }
                result.input_latency_ms = Some(started.elapsed().as_millis() as u64);
                let ws_url = self
                    .browser_sessions
                    .get(session_id)
                    .map(|s| s.endpoint.clone());
                browser_payload = Some(BrowserToolData {
                    session_id: session_id.clone(),
                    backend: "cdp".to_string(),
                    available: true,
                    note: "evaluated expression".to_string(),
                    screenshot_base64: None,
                    ws_url,
                    result_json: eval_result,
                });
            }
            ToolAction::BrowserClick {
                session_id,
                selector,
            } => {
                if !self.config.browser.enabled {
                    return Err("browser actions are disabled by daemon toolkit config".to_string());
                }
                if !self
                    .config
                    .browser
                    .backend
                    .trim()
                    .eq_ignore_ascii_case("cdp")
                {
                    return Err(format!(
                        "unsupported browser backend '{}' (expected 'cdp')",
                        self.config.browser.backend
                    ));
                }
                let started = Instant::now();
                let mut click_point = None;
                let res = self.with_browser_session(session_id, |session| {
                    let (x, y) = query_selector_center(session, selector)?;
                    dispatch_mouse_click(session, x, y)?;
                    click_point = Some(serde_json::json!({ "x": x, "y": y }));
                    Ok(())
                });
                if let Err(e) = res {
                    self.browser_sessions.remove(session_id);
                    return Err(e);
                }
                result.input_latency_ms = Some(started.elapsed().as_millis() as u64);
                let ws_url = self
                    .browser_sessions
                    .get(session_id)
                    .map(|s| s.endpoint.clone());
                browser_payload = Some(BrowserToolData {
                    session_id: session_id.clone(),
                    backend: "cdp".to_string(),
                    available: true,
                    note: format!("clicked selector {}", selector),
                    screenshot_base64: None,
                    ws_url,
                    result_json: click_point,
                });
            }
            ToolAction::BrowserType {
                session_id,
                selector,
                text,
            } => {
                if !self.config.browser.enabled {
                    return Err("browser actions are disabled by daemon toolkit config".to_string());
                }
                if !self
                    .config
                    .browser
                    .backend
                    .trim()
                    .eq_ignore_ascii_case("cdp")
                {
                    return Err(format!(
                        "unsupported browser backend '{}' (expected 'cdp')",
                        self.config.browser.backend
                    ));
                }
                let started = Instant::now();
                let mut typed_point = None;
                let res = self.with_browser_session(session_id, |session| {
                    let (x, y) = query_selector_center(session, selector)?;
                    dispatch_mouse_click(session, x, y)?;
                    session
                        .client
                        .call("Input.insertText", serde_json::json!({ "text": text }))?;
                    typed_point = Some(serde_json::json!({ "x": x, "y": y }));
                    Ok(())
                });
                if let Err(e) = res {
                    self.browser_sessions.remove(session_id);
                    return Err(e);
                }
                result.input_latency_ms = Some(started.elapsed().as_millis() as u64);
                let ws_url = self
                    .browser_sessions
                    .get(session_id)
                    .map(|s| s.endpoint.clone());
                browser_payload = Some(BrowserToolData {
                    session_id: session_id.clone(),
                    backend: "cdp".to_string(),
                    available: true,
                    note: format!("typed into selector {}", selector),
                    screenshot_base64: None,
                    ws_url,
                    result_json: typed_point,
                });
            }
            ToolAction::BrowserSnapshot {
                session_id,
                include_screenshot,
            } => {
                if !self.config.browser.enabled {
                    return Err("browser actions are disabled by daemon toolkit config".to_string());
                }
                if !self
                    .config
                    .browser
                    .backend
                    .trim()
                    .eq_ignore_ascii_case("cdp")
                {
                    return Err(format!(
                        "unsupported browser backend '{}' (expected 'cdp')",
                        self.config.browser.backend
                    ));
                }
                let allow_screenshot = self.config.browser.allow_screenshot;
                let started = Instant::now();
                let mut screenshot_base64 = None;
                let res = self.with_browser_session(session_id, |session| {
                    session.client.call("Page.enable", serde_json::json!({}))?;
                    if *include_screenshot && allow_screenshot {
                        let res = session.client.call(
                            "Page.captureScreenshot",
                            serde_json::json!({ "format": "png" }),
                        )?;
                        screenshot_base64 = res
                            .get("data")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                    }
                    Ok(())
                });
                if let Err(e) = res {
                    self.browser_sessions.remove(session_id);
                    return Err(e);
                }
                let ws_url = self
                    .browser_sessions
                    .get(session_id)
                    .map(|s| s.endpoint.clone());
                browser_payload = Some(BrowserToolData {
                    session_id: session_id.clone(),
                    backend: "cdp".to_string(),
                    available: true,
                    note: if *include_screenshot && !allow_screenshot {
                        "snapshot captured (screenshots disabled by toolkit policy config)"
                            .to_string()
                    } else {
                        "snapshot captured".to_string()
                    },
                    screenshot_base64,
                    ws_url,
                    result_json: None,
                });
                result.capture_latency_ms = Some(started.elapsed().as_millis() as u64);
            }
            ToolAction::BrowserProfileStart {
                session_id,
                headless,
                url,
            } => {
                if !self.config.browser.enabled {
                    return Err("browser actions are disabled by daemon toolkit config".to_string());
                }
                if !self
                    .config
                    .browser
                    .backend
                    .trim()
                    .eq_ignore_ascii_case("cdp")
                {
                    return Err(format!(
                        "unsupported browser backend '{}' (expected 'cdp')",
                        self.config.browser.backend
                    ));
                }
                let started = Instant::now();
                let ws_url = self.ensure_managed_browser(session_id, *headless, url.as_deref())?;
                result.input_latency_ms = Some(started.elapsed().as_millis() as u64);
                browser_payload = Some(BrowserToolData {
                    session_id: session_id.clone(),
                    backend: "cdp".to_string(),
                    available: true,
                    note: if *headless {
                        "browser profile ready (headless requested)".to_string()
                    } else {
                        "browser profile ready".to_string()
                    },
                    screenshot_base64: None,
                    ws_url: Some(ws_url),
                    result_json: None,
                });
            }
            ToolAction::BrowserProfileStop { session_id } => {
                if !self.config.browser.enabled {
                    return Err("browser actions are disabled by daemon toolkit config".to_string());
                }
                if !self
                    .config
                    .browser
                    .backend
                    .trim()
                    .eq_ignore_ascii_case("cdp")
                {
                    return Err(format!(
                        "unsupported browser backend '{}' (expected 'cdp')",
                        self.config.browser.backend
                    ));
                }
                let started = Instant::now();
                let stopped = self.stop_managed_browser(session_id);
                result.input_latency_ms = Some(started.elapsed().as_millis() as u64);
                result.session_id = Some(session_id.clone());
                browser_payload = Some(BrowserToolData {
                    session_id: session_id.clone(),
                    backend: "cdp".to_string(),
                    available: false,
                    note: if stopped {
                        "browser profile stopped".to_string()
                    } else {
                        "browser profile not active".to_string()
                    },
                    screenshot_base64: None,
                    ws_url: None,
                    result_json: None,
                });
            }
            ToolAction::InputBatch { actions } => {
                if !self.config.input.enabled {
                    return Err("input actions are disabled by daemon toolkit config".to_string());
                }
                let started = Instant::now();
                for action in actions {
                    self.apply_input_action(action).map_err(|e| e.to_string())?;
                }
                result.input_latency_ms = Some(started.elapsed().as_millis() as u64);
            }
            ToolAction::ImageAnalyze { .. } => {
                return Err(
                    "image analysis requires a vision backend (configure toolkit.vision in daemon.toml)"
                        .to_string(),
                );
            }
        }

        let execution = ToolActionExecution {
            result,
            risk_tag: mapping.risk_tag,
        };
        Ok(ToolkitOutput {
            execution,
            frame: frame_payload,
            tui: tui_payload,
            browser: browser_payload,
        })
    }

    /// Execute a batch of tool actions with budget enforcement.
    ///
    /// Respects the `ToolkitLoopExecutorConfig` from the daemon config:
    /// - `time_budget_ms`: stop if wall time exceeds budget
    /// - `max_micro_actions`: stop after N actions
    /// - `halt_on_high_risk`: stop if a High-risk action is encountered
    ///
    /// Returns partial results if halted early.
    pub fn execute_batch_with_budget(
        &mut self,
        actions: &[ToolAction],
    ) -> BatchResult {
        let time_budget_ms = self.config.loop_executor.time_budget_ms;
        let time_budget = Duration::from_millis(time_budget_ms);
        let max_micro_actions = self.config.loop_executor.max_micro_actions;
        let max_actions = max_micro_actions as usize;
        let halt_on_high_risk = self.config.loop_executor.halt_on_high_risk;

        let started = Instant::now();
        let mut completed = Vec::new();
        let mut halt_reason = None;

        for (i, action) in actions.iter().enumerate() {
            // Check time budget
            let elapsed = started.elapsed();
            if elapsed >= time_budget {
                halt_reason = Some(BatchHaltReason::TimeBudgetExceeded {
                    budget_ms: time_budget_ms,
                    elapsed_ms: elapsed.as_millis() as u64,
                });
                break;
            }

            // Check action count
            if i >= max_actions {
                halt_reason = Some(BatchHaltReason::MaxActionsReached {
                    max: max_micro_actions,
                    executed: i,
                });
                break;
            }

            // Check high-risk halt
            if halt_on_high_risk && action.risk_tag() == aegis_toolkit::contract::RiskTag::High {
                halt_reason = Some(BatchHaltReason::HighRiskHalt {
                    action_name: action.policy_action_name().to_string(),
                });
                break;
            }

            // Execute the action
            match self.execute(action) {
                Ok(output) => completed.push(output),
                Err(e) => {
                    halt_reason = Some(BatchHaltReason::ActionFailed {
                        action_name: action.policy_action_name().to_string(),
                        error: e,
                    });
                    break;
                }
            }
        }

        let elapsed_ms = started.elapsed().as_millis() as u64;

        BatchResult {
            executed_count: completed.len(),
            total_requested: actions.len(),
            completed,
            halt_reason,
            elapsed_ms,
        }
    }

    fn capture(&self, request: &CaptureRequest) -> Result<CaptureFrame, ToolkitError> {
        #[cfg(target_os = "macos")]
        {
            self.helper.capture_frame(request)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = request;
            Err(ToolkitError::Unavailable("capture not supported".into()))
        }
    }

    fn focus(&self, app_id: &str, window_id: Option<u64>) -> Result<(), ToolkitError> {
        #[cfg(target_os = "macos")]
        {
            self.helper.focus(&WindowRef {
                app_id: app_id.to_string(),
                window_id,
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (app_id, window_id);
            Err(ToolkitError::Unavailable(
                "window control not supported".into(),
            ))
        }
    }

    fn move_mouse(&self, x: i32, y: i32) -> Result<(), ToolkitError> {
        #[cfg(target_os = "macos")]
        {
            self.helper.move_mouse(&MouseMove { x, y })?;
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (x, y);
            Err(ToolkitError::Unavailable("input not supported".into()))
        }
    }

    fn click_mouse(&self, x: i32, y: i32, button: ContractMouseButton) -> Result<(), ToolkitError> {
        #[cfg(target_os = "macos")]
        {
            let btn = match button {
                ContractMouseButton::Left => MouseButton::Left,
                ContractMouseButton::Right => MouseButton::Right,
                ContractMouseButton::Middle => MouseButton::Middle,
            };
            self.helper.click_mouse(&MouseClick { x, y, button: btn })?;
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (x, y, button);
            Err(ToolkitError::Unavailable("input not supported".into()))
        }
    }

    fn drag_mouse(
        &self,
        from_x: i32,
        from_y: i32,
        to_x: i32,
        to_y: i32,
    ) -> Result<(), ToolkitError> {
        #[cfg(target_os = "macos")]
        {
            self.helper.move_mouse(&MouseMove {
                x: from_x,
                y: from_y,
            })?;
            self.helper.mouse_down(from_x, from_y, "left")?;
            self.helper.move_mouse(&MouseMove { x: to_x, y: to_y })?;
            self.helper.mouse_up(to_x, to_y, "left")?;
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (from_x, from_y, to_x, to_y);
            Err(ToolkitError::Unavailable("input not supported".into()))
        }
    }

    fn key_press(&self, key: &str) -> Result<(), ToolkitError> {
        #[cfg(target_os = "macos")]
        {
            self.helper.key_press(&KeyPress {
                key: key.to_string(),
            })?;
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = key;
            Err(ToolkitError::Unavailable("input not supported".into()))
        }
    }

    fn type_text(&self, text: &str) -> Result<(), ToolkitError> {
        #[cfg(target_os = "macos")]
        {
            self.helper.type_text(&TypeText {
                text: text.to_string(),
            })?;
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = text;
            Err(ToolkitError::Unavailable("input not supported".into()))
        }
    }

    fn apply_input_action(
        &self,
        action: &aegis_toolkit::contract::InputAction,
    ) -> Result<(), ToolkitError> {
        use aegis_toolkit::contract::InputAction;
        match action {
            InputAction::MouseMove { x, y } => self.move_mouse(*x, *y),
            InputAction::MouseClick { x, y, button } => self.click_mouse(*x, *y, button.clone()),
            InputAction::MouseDrag {
                from_x,
                from_y,
                to_x,
                to_y,
            } => self.drag_mouse(*from_x, *from_y, *to_x, *to_y),
            InputAction::KeyPress { keys } => {
                for key in keys {
                    self.key_press(key)?;
                }
                Ok(())
            }
            InputAction::TypeText { text } => self.type_text(text),
            InputAction::Wait { duration_ms } => {
                thread::sleep(Duration::from_millis(*duration_ms));
                Ok(())
            }
        }
    }

    pub fn prune_idle_sessions(&mut self, max_idle: Duration) {
        let now = Instant::now();
        self.browser_sessions
            .retain(|_, session| now.duration_since(session.last_used) <= max_idle);
        let expired: Vec<String> = self
            .managed_browsers
            .iter()
            .filter_map(|(id, browser)| {
                if now.duration_since(browser.last_used) > max_idle {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();
        for id in expired {
            let _ = self.stop_managed_browser(&id);
        }
    }

    fn with_browser_session<F>(&mut self, session_id: &str, f: F) -> Result<(), String>
    where
        F: FnOnce(&mut BrowserSession) -> Result<(), String>,
    {
        // Check max concurrent sessions before creating new one
        if !self.browser_sessions.contains_key(session_id) {
            let max = self.config.browser.max_concurrent_sessions;
            if max > 0 && self.browser_sessions.len() >= max as usize {
                return Err(format!(
                    "max concurrent browser sessions ({max}) reached, close an existing session first"
                ));
            }
        }

        let session = match self.browser_sessions.get_mut(session_id) {
            Some(session) => session,
            None => {
                let ws_override = self
                    .managed_browsers
                    .get(session_id)
                    .map(|browser| browser.ws_url.as_str());
                let (client, endpoint) =
                    CdpClient::connect(ws_override.or(self.config.browser.cdp_ws_url.as_deref()), self.config.browser.max_response_bytes)?;
                self.browser_sessions.insert(
                    session_id.to_string(),
                    BrowserSession {
                        client,
                        endpoint,
                        last_used: Instant::now(),
                    },
                );
                self.browser_sessions
                    .get_mut(session_id)
                    .expect("browser session just inserted")
            }
        };

        let res = f(session);
        if res.is_ok() {
            session.last_used = Instant::now();
            if let Some(browser) = self.managed_browsers.get_mut(session_id) {
                browser.last_used = Instant::now();
            }
        }
        res
    }

    pub fn shutdown(&mut self) {
        let ids: Vec<String> = self.managed_browsers.keys().cloned().collect();
        for id in ids {
            let _ = self.stop_managed_browser(&id);
        }
        self.browser_sessions.clear();
    }

    fn ensure_managed_browser(
        &mut self,
        session_id: &str,
        headless: bool,
        url: Option<&str>,
    ) -> Result<String, String> {
        if let Some(browser) = self.managed_browsers.get_mut(session_id) {
            browser.last_used = Instant::now();
            return Ok(browser.ws_url.clone());
        }

        let (child, ws_url, data_dir) = self.spawn_managed_browser(session_id, headless, url)?;
        let (client, endpoint) = CdpClient::connect(Some(&ws_url), self.config.browser.max_response_bytes)?;
        self.browser_sessions.insert(
            session_id.to_string(),
            BrowserSession {
                client,
                endpoint: endpoint.clone(),
                last_used: Instant::now(),
            },
        );
        self.managed_browsers.insert(
            session_id.to_string(),
            ManagedBrowser {
                child,
                ws_url: endpoint.clone(),
                last_used: Instant::now(),
                data_dir,
            },
        );
        Ok(endpoint)
    }

    fn stop_managed_browser(&mut self, session_id: &str) -> bool {
        let mut stopped = false;
        if let Some(mut browser) = self.managed_browsers.remove(session_id) {
            let _ = browser.child.kill();
            stopped = true;
        }
        if self.browser_sessions.remove(session_id).is_some() {
            stopped = true;
        }
        stopped
    }

    fn spawn_managed_browser(
        &self,
        session_id: &str,
        headless: bool,
        url: Option<&str>,
    ) -> Result<(Child, String, PathBuf), String> {
        let port = pick_ephemeral_port()?;
        let data_dir = self
            .config
            .browser
            .user_data_root
            .as_deref()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp/aegis-browser-profiles"))
            .join(session_id);
        fs::create_dir_all(&data_dir)
            .map_err(|e| format!("failed to create browser data dir: {e}"))?;

        let mut args = Vec::new();
        args.push(format!("--remote-debugging-port={port}"));
        args.push("--remote-debugging-address=127.0.0.1".to_string());
        args.push(format!("--user-data-dir={}", data_dir.display()));
        args.push("--no-first-run".to_string());
        args.push("--no-default-browser-check".to_string());
        args.push("--disable-popup-blocking".to_string());
        if headless {
            args.push("--headless=new".to_string());
            args.push("--disable-gpu".to_string());
        }
        for extra in &self.config.browser.extra_args {
            if !extra.trim().is_empty() {
                args.push(extra.to_string());
            }
        }
        if let Some(u) = url.filter(|u| !u.trim().is_empty()) {
            args.push(u.to_string());
        }

        let mut last_error = None;
        let mut child = None;
        for candidate in browser_binary_candidates(self.config.browser.binary_path.as_deref()) {
            let mut cmd = Command::new(&candidate);
            cmd.args(&args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            match cmd.spawn() {
                Ok(proc) => {
                    child = Some(proc);
                    break;
                }
                Err(e) => {
                    last_error = Some(format!("{candidate}: {e}"));
                }
            }
        }
        let mut child = child.ok_or_else(|| {
            format!(
                "failed to launch browser: {}",
                last_error.unwrap_or_else(|| "no candidates available".to_string())
            )
        })?;

        let ws_url = match wait_for_cdp_ws(port, Duration::from_secs(3)) {
            Ok(ws) => ws,
            Err(e) => {
                let _ = child.kill();
                return Err(e);
            }
        };

        Ok((child, ws_url, data_dir))
    }
}

fn tui_target(data: &TuiToolData) -> &str {
    match data {
        TuiToolData::Snapshot { target, .. } | TuiToolData::Input { target, .. } => target,
    }
}

struct BrowserSession {
    client: CdpClient,
    #[allow(dead_code)]
    endpoint: String,
    last_used: Instant,
}

struct ManagedBrowser {
    child: Child,
    ws_url: String,
    last_used: Instant,
    #[allow(dead_code)]
    data_dir: PathBuf,
}

fn browser_binary_candidates(configured: Option<&str>) -> Vec<String> {
    let mut candidates = Vec::new();
    if let Some(path) = configured {
        if !path.trim().is_empty() {
            candidates.push(path.to_string());
        }
    }
    if let Ok(env_path) = env::var("AEGIS_BROWSER_BIN") {
        if !env_path.trim().is_empty() {
            candidates.push(env_path);
        }
    }
    candidates.extend(
        [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
        ]
        .iter()
        .map(|s| s.to_string()),
    );
    candidates.extend(
        ["google-chrome", "chromium", "chrome"]
            .iter()
            .map(|s| s.to_string()),
    );
    candidates
}

fn pick_ephemeral_port() -> Result<u16, String> {
    let listener =
        TcpListener::bind("127.0.0.1:0").map_err(|e| format!("port bind failed: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("port lookup failed: {e}"))?
        .port();
    Ok(port)
}

fn wait_for_cdp_ws(port: u16, timeout: Duration) -> Result<String, String> {
    let deadline = Instant::now() + timeout;
    let url = format!("http://127.0.0.1:{port}/json/version");
    while Instant::now() < deadline {
        if let Ok(resp) = reqwest::blocking::get(&url) {
            if let Ok(value) = resp.json::<serde_json::Value>() {
                if let Some(ws) = value.get("webSocketDebuggerUrl").and_then(|v| v.as_str()) {
                    return Ok(ws.to_string());
                }
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err(format!("timed out waiting for CDP endpoint on {url}"))
}

struct CdpClient {
    socket: WebSocket<MaybeTlsStream<TcpStream>>,
    next_id: u64,
    ws_url: String,
    max_response_bytes: usize,
}

impl CdpClient {
    fn connect(ws_url_override: Option<&str>, max_response_bytes: usize) -> Result<(Self, String), String> {
        let ws_url = match ws_url_override {
            Some(url) if !url.trim().is_empty() => url.to_string(),
            _ => env::var("AEGIS_CDP_WS")
                .or_else(|_| env::var("CHROME_DEVTOOLS_WS"))
                .map_err(|_| {
                    "missing CDP websocket endpoint (set toolkit.browser.cdp_ws_url or AEGIS_CDP_WS/CHROME_DEVTOOLS_WS)"
                        .to_string()
                })?,
        };

        let url = Url::parse(&ws_url)
            .map_err(|e| format!("invalid CDP websocket URL ({ws_url}): {e}"))?;
        let (socket, _) = connect(url).map_err(|e| format!("cdp connect failed: {e}"))?;

        Ok((Self { socket, next_id: 1, ws_url: ws_url.clone(), max_response_bytes }, ws_url))
    }

    fn reconnect(&mut self) -> Result<(), String> {
        let url = Url::parse(&self.ws_url)
            .map_err(|e| format!("invalid CDP URL for reconnect: {e}"))?;
        let (socket, _) = connect(url)
            .map_err(|e| format!("cdp reconnect failed: {e}"))?;
        self.socket = socket;
        self.next_id = 1;
        Ok(())
    }

    fn call(
        &mut self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        match self.call_inner(method, &params) {
            Ok(v) => Ok(v),
            Err(e) if e.contains("cdp send failed") || e.contains("cdp read failed") || e.contains("cdp socket closed") => {
                tracing::warn!(error = %e, "CDP socket error, attempting reconnect");
                self.reconnect()?;
                self.call_inner(method, &params)
            }
            Err(e) => Err(e),
        }
    }

    fn call_inner(
        &mut self,
        method: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let id = self.next_id;
        self.next_id += 1;

        let payload = serde_json::json!({
            "id": id,
            "method": method,
            "params": params,
        });
        let text = payload.to_string();
        self.socket
            .send(Message::Text(text))
            .map_err(|e| format!("cdp send failed: {e}"))?;

        loop {
            let msg = self
                .socket
                .read()
                .map_err(|e| format!("cdp read failed: {e}"))?;
            let text = match msg {
                Message::Text(text) => {
                    if self.max_response_bytes > 0 && text.len() > self.max_response_bytes {
                        return Err(format!(
                            "CDP response too large ({} bytes, limit {} bytes)",
                            text.len(),
                            self.max_response_bytes
                        ));
                    }
                    text
                }
                Message::Binary(bytes) => {
                    if self.max_response_bytes > 0 && bytes.len() > self.max_response_bytes {
                        return Err(format!(
                            "CDP response too large ({} bytes, limit {} bytes)",
                            bytes.len(),
                            self.max_response_bytes
                        ));
                    }
                    String::from_utf8(bytes)
                        .map_err(|e| format!("cdp binary decode failed: {e}"))?
                }
                Message::Ping(_) | Message::Pong(_) => continue,
                Message::Close(_) => return Err("cdp socket closed".to_string()),
                _ => continue,
            };

            let value: serde_json::Value =
                serde_json::from_str(&text).map_err(|e| format!("cdp json failed: {e}"))?;
            if value.get("id").and_then(|v| v.as_u64()) != Some(id) {
                continue;
            }
            if let Some(error) = value.get("error") {
                return Err(format!("cdp error: {error}"));
            }

            return Ok(value
                .get("result")
                .cloned()
                .unwrap_or(serde_json::Value::Null));
        }
    }
}

fn query_selector_center(
    session: &mut BrowserSession,
    selector: &str,
) -> Result<(f64, f64), String> {
    session.client.call("DOM.enable", serde_json::json!({}))?;
    session.client.call("Page.enable", serde_json::json!({}))?;
    let document = session
        .client
        .call("DOM.getDocument", serde_json::json!({ "depth": 1 }))?;
    let root_id = document
        .get("root")
        .and_then(|v| v.get("nodeId"))
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing root node id from DOM.getDocument".to_string())?;
    let found = session.client.call(
        "DOM.querySelector",
        serde_json::json!({ "nodeId": root_id, "selector": selector }),
    )?;
    let node_id = found.get("nodeId").and_then(|v| v.as_u64()).unwrap_or(0);
    if node_id == 0 {
        return Err(format!("selector not found: {selector}"));
    }
    let box_model = session
        .client
        .call("DOM.getBoxModel", serde_json::json!({ "nodeId": node_id }))?;
    let content = box_model
        .get("model")
        .and_then(|v| v.get("content"))
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing box model content".to_string())?;
    if content.len() < 8 {
        return Err("insufficient box model points".to_string());
    }
    let mut xs = Vec::new();
    let mut ys = Vec::new();
    for (idx, value) in content.iter().enumerate() {
        let number = value
            .as_f64()
            .ok_or_else(|| "non-numeric box model coordinate".to_string())?;
        if idx % 2 == 0 {
            xs.push(number);
        } else {
            ys.push(number);
        }
    }
    let x = xs.iter().sum::<f64>() / xs.len() as f64;
    let y = ys.iter().sum::<f64>() / ys.len() as f64;
    Ok((x, y))
}

fn dispatch_mouse_click(session: &mut BrowserSession, x: f64, y: f64) -> Result<(), String> {
    session.client.call(
        "Input.dispatchMouseEvent",
        serde_json::json!({
            "type": "mousePressed",
            "x": x,
            "y": y,
            "button": "left",
            "clickCount": 1
        }),
    )?;
    session.client.call(
        "Input.dispatchMouseEvent",
        serde_json::json!({
            "type": "mouseReleased",
            "x": x,
            "y": y,
            "button": "left",
            "clickCount": 1
        }),
    )?;
    Ok(())
}

fn frame_to_payload(frame: CaptureFrame) -> Result<FramePayload, String> {
    let rgba_base64 = B64.encode(frame.rgba);
    Ok(FramePayload {
        width: frame.metadata.width,
        height: frame.metadata.height,
        rgba_base64,
    })
}
