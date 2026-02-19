//! macOS helper client for capture/input/window control.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Mutex;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};

use crate::capture::{CaptureProvider, CaptureRequest};
use crate::input::{InputProvider, KeyPress, MouseClick, MouseMove, TypeText};
use crate::tui::{TuiInput, TuiProvider, TuiSnapshot};
use crate::window::{WindowProvider, WindowRef};
use crate::{CaptureFrame, FrameMetadata, InputLatency, ToolkitError, ToolkitResult};

#[derive(Debug, Serialize)]
struct Request<'a> {
    op: &'a str,
    region: Option<Region>,
    x: Option<i32>,
    y: Option<i32>,
    button: Option<&'a str>,
    text: Option<&'a str>,
    key: Option<&'a str>,
    app_id: Option<&'a str>,
    window_id: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
struct Region {
    x: i32,
    y: i32,
    width: i32,
    height: i32,
}

#[derive(Debug, Deserialize)]
struct Response {
    ok: bool,
    error: Option<String>,
    width: Option<u32>,
    height: Option<u32>,
    rgba_base64: Option<String>,
}

pub struct MacosHelper {
    child: Mutex<Child>,
    stdin: Mutex<ChildStdin>,
    stdout: Mutex<BufReader<ChildStdout>>,
}

impl MacosHelper {
    pub fn spawn() -> ToolkitResult<Self> {
        let helper = std::env::var("AEGIS_MACOS_HELPER").unwrap_or_else(|_| {
            "tools/aegis-macos-helper/.build/release/aegis-macos-helper".to_string()
        });

        let mut cmd = Command::new(helper);
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit());

        let mut child = cmd.spawn().map_err(|e| {
            ToolkitError::Unavailable(format!("failed to spawn macos helper: {e}"))
        })?;
        let stdin = child.stdin.take().ok_or_else(|| {
            ToolkitError::Unavailable("helper stdin not available".into())
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            ToolkitError::Unavailable("helper stdout not available".into())
        })?;

        Ok(Self {
            child: Mutex::new(child),
            stdin: Mutex::new(stdin),
            stdout: Mutex::new(BufReader::new(stdout)),
        })
    }

    fn send(&self, req: &Request<'_>) -> ToolkitResult<Response> {
        let payload = serde_json::to_string(req)
            .map_err(|e| ToolkitError::Other(format!("serialize request: {e}")))?;
        {
            let mut stdin = self.stdin.lock().map_err(|_| ToolkitError::Other("stdin lock".into()))?;
            stdin.write_all(payload.as_bytes())
                .map_err(|e| ToolkitError::Other(format!("stdin write: {e}")))?;
            stdin.write_all(b"\n")
                .map_err(|e| ToolkitError::Other(format!("stdin write: {e}")))?;
            stdin.flush().ok();
        }

        let mut line = String::new();
        let mut stdout = self.stdout.lock().map_err(|_| ToolkitError::Other("stdout lock".into()))?;
        stdout.read_line(&mut line)
            .map_err(|e| ToolkitError::Other(format!("stdout read: {e}")))?;

        let resp: Response = serde_json::from_str(line.trim())
            .map_err(|e| ToolkitError::Other(format!("deserialize response: {e}")))?;
        if resp.ok {
            Ok(resp)
        } else {
            Err(ToolkitError::Other(resp.error.unwrap_or_else(|| "unknown error".into())))
        }
    }
}

impl CaptureProvider for MacosHelper {
    fn start(&self, _request: &CaptureRequest) -> ToolkitResult<()> {
        Ok(())
    }

    fn next_frame(&self) -> ToolkitResult<CaptureFrame> {
        let resp = self.send(&Request {
            op: "capture",
            region: None,
            x: None,
            y: None,
            button: None,
            text: None,
            key: None,
            app_id: None,
            window_id: None,
        })?;

        let width = resp.width.ok_or_else(|| ToolkitError::Other("missing width".into()))?;
        let height = resp.height.ok_or_else(|| ToolkitError::Other("missing height".into()))?;
        let b64 = resp.rgba_base64.ok_or_else(|| ToolkitError::Other("missing rgba".into()))?;
        let rgba = B64.decode(b64.as_bytes())
            .map_err(|e| ToolkitError::Other(format!("decode rgba: {e}")))?;

        Ok(CaptureFrame {
            metadata: FrameMetadata {
                width,
                height,
                timestamp_ms: 0,
                frame_id: 0,
            },
            rgba,
        })
    }

    fn stop(&self) -> ToolkitResult<()> {
        Ok(())
    }
}

impl InputProvider for MacosHelper {
    fn move_mouse(&self, req: &MouseMove) -> ToolkitResult<InputLatency> {
        self.send(&Request {
            op: "mouse_move",
            region: None,
            x: Some(req.x),
            y: Some(req.y),
            button: None,
            text: None,
            key: None,
            app_id: None,
            window_id: None,
        })?;
        Ok(InputLatency { latency_ms: 0 })
    }

    fn click_mouse(&self, req: &MouseClick) -> ToolkitResult<InputLatency> {
        let button = match req.button {
            crate::input::MouseButton::Left => "left",
            crate::input::MouseButton::Right => "right",
            crate::input::MouseButton::Middle => "middle",
        };
        self.send(&Request {
            op: "mouse_click",
            region: None,
            x: Some(req.x),
            y: Some(req.y),
            button: Some(button),
            text: None,
            key: None,
            app_id: None,
            window_id: None,
        })?;
        Ok(InputLatency { latency_ms: 0 })
    }

    fn key_press(&self, req: &KeyPress) -> ToolkitResult<InputLatency> {
        self.send(&Request {
            op: "key_press",
            region: None,
            x: None,
            y: None,
            button: None,
            text: None,
            key: Some(req.key.as_str()),
            app_id: None,
            window_id: None,
        })?;
        Ok(InputLatency { latency_ms: 0 })
    }

    fn type_text(&self, req: &TypeText) -> ToolkitResult<InputLatency> {
        self.send(&Request {
            op: "type_text",
            region: None,
            x: None,
            y: None,
            button: None,
            text: Some(req.text.as_str()),
            key: None,
            app_id: None,
            window_id: None,
        })?;
        Ok(InputLatency { latency_ms: 0 })
    }
}

impl WindowProvider for MacosHelper {
    fn focus(&self, req: &WindowRef) -> ToolkitResult<()> {
        self.send(&Request {
            op: "focus",
            region: None,
            x: None,
            y: None,
            button: None,
            text: None,
            key: None,
            app_id: Some(req.app_id.as_str()),
            window_id: req.window_id.map(|v| v as u32),
        })?;
        Ok(())
    }
}

impl TuiProvider for MacosHelper {
    fn snapshot(&self, _session_id: &str) -> ToolkitResult<TuiSnapshot> {
        Err(ToolkitError::Unavailable("tui snapshot not implemented".into()))
    }

    fn send_input(&self, _session_id: &str, _input: &TuiInput) -> ToolkitResult<()> {
        Err(ToolkitError::Unavailable("tui input not implemented".into()))
    }
}

impl Drop for MacosHelper {
    fn drop(&mut self) {
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
        }
    }
}
