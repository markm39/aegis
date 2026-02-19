//! Orchestrator computer-use runtime backed by aegis-toolkit.

use std::time::Instant;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

use aegis_control::daemon::ToolActionExecution;
use aegis_toolkit::capture::CaptureRequest;
use aegis_toolkit::contract::{MouseButton as ContractMouseButton, ToolAction, ToolResult};
use aegis_toolkit::input::{InputProvider, KeyPress, MouseButton, MouseClick, MouseMove, TypeText};
use aegis_toolkit::policy::map_tool_action;
use aegis_toolkit::window::{WindowProvider, WindowRef};
use aegis_toolkit::{CaptureFrame, ToolkitError};

#[derive(Debug, Clone, serde::Serialize)]
pub struct FramePayload {
    pub width: u32,
    pub height: u32,
    pub rgba_base64: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ToolkitOutput {
    pub execution: ToolActionExecution,
    pub frame: Option<FramePayload>,
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
            return Ok(Self { helper });
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
            ToolAction::BrowserNavigate { .. } | ToolAction::BrowserSnapshot { .. } => {
                return Err("browser runtime not implemented (CDP backend missing)".to_string());
            }
        }

        let execution = ToolActionExecution {
            result,
            risk_tag: mapping.risk_tag,
        };
        Ok(ToolkitOutput {
            execution,
            frame: frame_payload,
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
            self.helper.move_mouse(&MouseMove { x: to_x, y: to_y })?;
            self.helper.click_mouse(&MouseClick {
                x: to_x,
                y: to_y,
                button: MouseButton::Left,
            })?;
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

fn frame_to_payload(frame: CaptureFrame) -> Result<FramePayload, String> {
    let rgba_base64 = B64.encode(frame.rgba);
    Ok(FramePayload {
        width: frame.metadata.width,
        height: frame.metadata.height,
        rgba_base64,
    })
}
