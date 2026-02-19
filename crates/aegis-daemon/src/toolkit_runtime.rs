//! Orchestrator computer-use runtime backed by aegis-toolkit.

use std::env;
use std::net::TcpStream;
use std::time::Instant;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

use aegis_control::daemon::{BrowserToolData, FramePayload, ToolActionExecution};
use aegis_toolkit::capture::CaptureRequest;
use aegis_toolkit::contract::{MouseButton as ContractMouseButton, ToolAction, ToolResult};
use aegis_toolkit::input::{InputProvider, KeyPress, MouseButton, MouseClick, MouseMove, TypeText};
use aegis_toolkit::policy::map_tool_action;
use aegis_toolkit::window::{WindowProvider, WindowRef};
use aegis_toolkit::{CaptureFrame, ToolkitError};

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
    #[cfg(target_os = "macos")]
    helper: aegis_toolkit::macos_helper::MacosHelper,
}

impl ToolkitRuntime {
    pub fn new() -> Result<Self, String> {
        #[cfg(target_os = "macos")]
        {
            let helper = aegis_toolkit::macos_helper()
                .map_err(|e| format!("macos helper unavailable: {e}"))?;
            Ok(Self { helper })
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err("toolkit runtime only implemented on macOS".to_string())
        }
    }

    pub fn execute(&self, action: &ToolAction) -> Result<ToolkitOutput, String> {
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
                let started = Instant::now();
                self.focus(app_id, *window_id).map_err(|e| e.to_string())?;
                result.input_latency_ms = Some(started.elapsed().as_millis() as u64);
                result.window_id = *window_id;
            }
            ToolAction::MouseMove { x, y } => {
                let started = Instant::now();
                self.move_mouse(*x, *y).map_err(|e| e.to_string())?;
                result.input_latency_ms = Some(started.elapsed().as_millis() as u64);
            }
            ToolAction::MouseClick { x, y, button } => {
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
                let started = Instant::now();
                self.drag_mouse(*from_x, *from_y, *to_x, *to_y)
                    .map_err(|e| e.to_string())?;
                result.input_latency_ms = Some(started.elapsed().as_millis() as u64);
            }
            ToolAction::KeyPress { keys } => {
                let started = Instant::now();
                for key in keys {
                    self.key_press(key).map_err(|e| e.to_string())?;
                }
                result.input_latency_ms = Some(started.elapsed().as_millis() as u64);
            }
            ToolAction::TypeText { text } => {
                let started = Instant::now();
                self.type_text(text).map_err(|e| e.to_string())?;
                result.input_latency_ms = Some(started.elapsed().as_millis() as u64);
            }
            ToolAction::TuiSnapshot { .. } | ToolAction::TuiInput { .. } => {
                return Err("tui runtime not implemented".to_string());
            }
            ToolAction::BrowserNavigate { session_id, url } => {
                let started = Instant::now();
                let mut client = CdpClient::connect_from_env()?;
                client.call("Page.enable", serde_json::json!({}))?;
                client.call("Page.navigate", serde_json::json!({ "url": url }))?;
                result.input_latency_ms = Some(started.elapsed().as_millis() as u64);
                browser_payload = Some(BrowserToolData {
                    session_id: session_id.clone(),
                    backend: "cdp".to_string(),
                    available: true,
                    note: "navigated".to_string(),
                    screenshot_base64: None,
                });
            }
            ToolAction::BrowserSnapshot {
                session_id,
                include_screenshot,
            } => {
                let started = Instant::now();
                let mut client = CdpClient::connect_from_env()?;
                client.call("Page.enable", serde_json::json!({}))?;
                let screenshot_base64 = if *include_screenshot {
                    let res = client.call("Page.captureScreenshot", serde_json::json!({ "format": "png" }))?;
                    res.get("data").and_then(|v| v.as_str()).map(|s| s.to_string())
                } else {
                    None
                };
                browser_payload = Some(BrowserToolData {
                    session_id: session_id.clone(),
                    backend: "cdp".to_string(),
                    available: true,
                    note: "snapshot captured".to_string(),
                    screenshot_base64,
                });
                result.capture_latency_ms = Some(started.elapsed().as_millis() as u64);
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
}

struct CdpClient {
    socket: WebSocket<MaybeTlsStream<TcpStream>>,
    next_id: u64,
}

impl CdpClient {
    fn connect_from_env() -> Result<Self, String> {
        let ws_url = env::var("AEGIS_CDP_WS")
            .or_else(|_| env::var("CHROME_DEVTOOLS_WS"))
            .map_err(|_| {
                "missing CDP websocket endpoint (set AEGIS_CDP_WS or CHROME_DEVTOOLS_WS)"
                    .to_string()
            })?;

        let url = Url::parse(&ws_url)
            .map_err(|e| format!("invalid CDP websocket URL ({ws_url}): {e}"))?;
        let (socket, _) = connect(url).map_err(|e| format!("cdp connect failed: {e}"))?;

        Ok(Self { socket, next_id: 1 })
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
