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

use aegis_control::daemon::{BrowserToolData, FramePayload, ToolActionExecution};
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
    pub browser: Option<BrowserToolData>,
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
            ToolAction::TuiSnapshot { .. } | ToolAction::TuiInput { .. } => {
                return Err("tui runtime not implemented".to_string());
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
                        screenshot_base64 =
                            res.get("data").and_then(|v| v.as_str()).map(|s| s.to_string());
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
        }

        let execution = ToolActionExecution {
            result,
            risk_tag: mapping.risk_tag,
        };
        Ok(ToolkitOutput {
            execution,
            frame: frame_payload,
            browser: browser_payload,
        })
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

    fn apply_input_action(&self, action: &aegis_toolkit::contract::InputAction) -> Result<(), ToolkitError> {
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
            self.stop_managed_browser(&id);
        }
    }

    fn with_browser_session<F>(&mut self, session_id: &str, f: F) -> Result<(), String>
    where
        F: FnOnce(&mut BrowserSession) -> Result<(), String>,
    {
        let session = match self.browser_sessions.get_mut(session_id) {
            Some(session) => session,
            None => {
                let ws_override = self
                    .managed_browsers
                    .get(session_id)
                    .map(|browser| browser.ws_url.as_str());
                let (client, endpoint) = CdpClient::connect(
                    ws_override.or(self.config.browser.cdp_ws_url.as_deref()),
                )?;
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
            self.stop_managed_browser(&id);
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

        let (child, ws_url, data_dir) =
            self.spawn_managed_browser(session_id, headless, url)?;
        let (client, endpoint) = CdpClient::connect(Some(&ws_url))?;
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

    fn stop_managed_browser(&mut self, session_id: &str) {
        if let Some(mut browser) = self.managed_browsers.remove(session_id) {
            let _ = browser.child.kill();
        }
        self.browser_sessions.remove(session_id);
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
        match reqwest::blocking::get(&url) {
            Ok(resp) => {
                if let Ok(value) = resp.json::<serde_json::Value>() {
                    if let Some(ws) = value
                        .get("webSocketDebuggerUrl")
                        .and_then(|v| v.as_str())
                    {
                        return Ok(ws.to_string());
                    }
                }
            }
            Err(_) => {}
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err(format!("timed out waiting for CDP endpoint on {url}"))
}

struct CdpClient {
    socket: WebSocket<MaybeTlsStream<TcpStream>>,
    next_id: u64,
}

impl CdpClient {
    fn connect(ws_url_override: Option<&str>) -> Result<(Self, String), String> {
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

        Ok((Self { socket, next_id: 1 }, ws_url))
    }

    fn call(&mut self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
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
                Message::Text(text) => text,
                Message::Binary(bytes) => String::from_utf8(bytes)
                    .map_err(|e| format!("cdp binary decode failed: {e}"))?,
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

            return Ok(value.get("result").cloned().unwrap_or(serde_json::Value::Null));
        }
    }
}

fn frame_to_payload(frame: CaptureFrame) -> Result<FramePayload, String> {
    let rgba_base64 = B64.encode(frame.rgba);
    Ok(FramePayload {
        width: frame.metadata.width,
        height: frame.metadata.height,
        rgba_base64,
    })
}
