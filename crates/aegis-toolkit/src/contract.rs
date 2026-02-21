//! Phase-0 contract for orchestrator computer-use loops.
//!
//! Defines the action taxonomy, risk tags, and latency envelope so runtime
//! implementations can stay policy-gated and measurable.

use serde::{Deserialize, Serialize};

/// Latency targets for high-speed sense/act loops.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct FastLoopEnvelope {
    /// Target capture cadence in frames per second.
    pub target_fps: u16,
    /// Median capture latency budget in milliseconds.
    pub max_capture_latency_ms: u16,
    /// Median input latency budget in milliseconds.
    pub max_input_latency_ms: u16,
    /// Lower bound for micro-actions per plan step.
    pub min_micro_actions: u8,
    /// Upper bound for micro-actions per plan step.
    pub max_micro_actions: u8,
}

impl FastLoopEnvelope {
    /// Default operational envelope for orchestrator computer-use.
    pub const fn default_contract() -> Self {
        Self {
            target_fps: 30,
            max_capture_latency_ms: 100,
            max_input_latency_ms: 50,
            min_micro_actions: 3,
            max_micro_actions: 10,
        }
    }
}

/// Risk class used by policy/approval layers.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RiskTag {
    Low,
    Medium,
    High,
}

/// Declarative actions that the orchestrator runtime may attempt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ToolAction {
    ScreenCapture {
        region: Option<CaptureRegion>,
        target_fps: u16,
    },
    WindowFocus {
        app_id: String,
        window_id: Option<u64>,
    },
    MouseMove {
        x: i32,
        y: i32,
    },
    MouseClick {
        x: i32,
        y: i32,
        button: MouseButton,
    },
    MouseDrag {
        from_x: i32,
        from_y: i32,
        to_x: i32,
        to_y: i32,
    },
    KeyPress {
        keys: Vec<String>,
    },
    TypeText {
        text: String,
    },
    TuiSnapshot {
        session_id: String,
    },
    TuiInput {
        session_id: String,
        text: String,
    },
    /// Navigate to a URL in the browser.
    ///
    /// Integration point: callers MUST validate `url` through
    /// [`crate::navigation_guard::NavigationGuard::validate_url`] before executing
    /// this action. The guard enforces scheme restrictions, host deny/allowlists,
    /// private-network blocking, and DNS rebinding protection.
    BrowserNavigate {
        session_id: String,
        url: String,
    },
    BrowserEvaluate {
        session_id: String,
        expression: String,
        #[serde(default = "default_true")]
        return_by_value: bool,
    },
    BrowserClick {
        session_id: String,
        selector: String,
    },
    BrowserType {
        session_id: String,
        selector: String,
        text: String,
    },
    BrowserSnapshot {
        session_id: String,
        include_screenshot: bool,
    },
    BrowserProfileStart {
        session_id: String,
        #[serde(default)]
        headless: bool,
        #[serde(default)]
        url: Option<String>,
    },
    BrowserProfileStop {
        session_id: String,
    },
    InputBatch {
        actions: Vec<InputAction>,
    },
    ImageAnalyze {
        session_id: String,
        #[serde(default)]
        region: Option<CaptureRegion>,
    },
    /// Text-to-speech synthesis (stub -- not yet available).
    TextToSpeech {
        text: String,
        voice: Option<String>,
    },
    /// Canvas/drawing render action (stub -- not yet available).
    CanvasRender {
        canvas_action: String,
        params: serde_json::Value,
    },
    /// Device/hardware control action (stub -- not yet available).
    DeviceControl {
        device: String,
        command: String,
    },
}

impl ToolAction {
    /// Stable policy identifier for Cedar/action logs.
    pub fn policy_action_name(&self) -> &'static str {
        match self {
            ToolAction::ScreenCapture { .. } => "ScreenCapture",
            ToolAction::WindowFocus { .. } => "WindowFocus",
            ToolAction::MouseMove { .. } => "MouseMove",
            ToolAction::MouseClick { .. } => "MouseClick",
            ToolAction::MouseDrag { .. } => "MouseDrag",
            ToolAction::KeyPress { .. } => "KeyPress",
            ToolAction::TypeText { .. } => "TypeText",
            ToolAction::TuiSnapshot { .. } => "TuiSnapshot",
            ToolAction::TuiInput { .. } => "TuiInput",
            ToolAction::BrowserNavigate { .. } => "BrowserNavigate",
            ToolAction::BrowserEvaluate { .. } => "BrowserEvaluate",
            ToolAction::BrowserClick { .. } => "BrowserClick",
            ToolAction::BrowserType { .. } => "BrowserType",
            ToolAction::BrowserSnapshot { .. } => "BrowserSnapshot",
            ToolAction::BrowserProfileStart { .. } => "BrowserProfileStart",
            ToolAction::BrowserProfileStop { .. } => "BrowserProfileStop",
            ToolAction::InputBatch { .. } => "InputBatch",
            ToolAction::ImageAnalyze { .. } => "ImageAnalyze",
            ToolAction::TextToSpeech { .. } => "TextToSpeech",
            ToolAction::CanvasRender { .. } => "CanvasRender",
            ToolAction::DeviceControl { .. } => "DeviceControl",
        }
    }

    /// Risk class for policy defaulting and approval UX.
    pub fn risk_tag(&self) -> RiskTag {
        match self {
            ToolAction::ScreenCapture { .. }
            | ToolAction::MouseMove { .. }
            | ToolAction::TuiSnapshot { .. }
            | ToolAction::BrowserSnapshot { .. } => RiskTag::Low,
            ToolAction::MouseClick { .. }
            | ToolAction::MouseDrag { .. }
            | ToolAction::KeyPress { .. }
            | ToolAction::TypeText { .. }
            | ToolAction::TuiInput { .. }
            | ToolAction::BrowserClick { .. }
            | ToolAction::BrowserType { .. } => RiskTag::Medium,
            ToolAction::WindowFocus { .. }
            | ToolAction::BrowserNavigate { .. }
            | ToolAction::BrowserEvaluate { .. }
            | ToolAction::BrowserProfileStart { .. }
            | ToolAction::BrowserProfileStop { .. } => RiskTag::High,
            ToolAction::InputBatch { actions } => {
                max_risk_tag(actions.iter().map(InputAction::risk_tag))
            }
            ToolAction::ImageAnalyze { .. } => RiskTag::Medium,
            ToolAction::TextToSpeech { .. } => RiskTag::Medium,
            ToolAction::CanvasRender { .. } => RiskTag::Medium,
            ToolAction::DeviceControl { .. } => RiskTag::Medium,
        }
    }
}

fn max_risk_tag<I>(tags: I) -> RiskTag
where
    I: IntoIterator<Item = RiskTag>,
{
    let mut max = RiskTag::Low;
    for tag in tags {
        if risk_rank(tag) > risk_rank(max) {
            max = tag;
        }
    }
    max
}

fn risk_rank(tag: RiskTag) -> u8 {
    match tag {
        RiskTag::Low => 0,
        RiskTag::Medium => 1,
        RiskTag::High => 2,
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InputAction {
    MouseMove {
        x: i32,
        y: i32,
    },
    MouseClick {
        x: i32,
        y: i32,
        button: MouseButton,
    },
    MouseDrag {
        from_x: i32,
        from_y: i32,
        to_x: i32,
        to_y: i32,
    },
    KeyPress {
        keys: Vec<String>,
    },
    TypeText {
        text: String,
    },
    Wait {
        duration_ms: u64,
    },
}

impl InputAction {
    pub fn risk_tag(&self) -> RiskTag {
        match self {
            InputAction::MouseMove { .. } => RiskTag::Low,
            InputAction::MouseClick { .. }
            | InputAction::MouseDrag { .. }
            | InputAction::KeyPress { .. }
            | InputAction::TypeText { .. } => RiskTag::Medium,
            InputAction::Wait { .. } => RiskTag::Low,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaptureRegion {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MouseButton {
    Left,
    Right,
    Middle,
}

/// Runtime execution metadata for auditing and SLO checks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolResult {
    pub action: String,
    pub risk_tag: RiskTag,
    pub capture_latency_ms: Option<u64>,
    pub input_latency_ms: Option<u64>,
    pub frame_id: Option<u64>,
    pub window_id: Option<u64>,
    pub session_id: Option<String>,
    pub note: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_envelope_matches_phase_zero_targets() {
        let env = FastLoopEnvelope::default_contract();
        assert_eq!(env.target_fps, 30);
        assert_eq!(env.max_capture_latency_ms, 100);
        assert_eq!(env.max_input_latency_ms, 50);
        assert_eq!(env.min_micro_actions, 3);
        assert_eq!(env.max_micro_actions, 10);
    }

    #[test]
    fn tool_action_roundtrip_serde() {
        let action = ToolAction::MouseClick {
            x: 120,
            y: 340,
            button: MouseButton::Left,
        };
        let json = serde_json::to_string(&action).unwrap();
        let back: ToolAction = serde_json::from_str(&json).unwrap();
        assert_eq!(action, back);
    }

    #[test]
    fn input_batch_roundtrip_serde() {
        let action = ToolAction::InputBatch {
            actions: vec![
                InputAction::MouseMove { x: 1, y: 2 },
                InputAction::TypeText { text: "hi".into() },
                InputAction::Wait { duration_ms: 10 },
            ],
        };
        let json = serde_json::to_string(&action).unwrap();
        let back: ToolAction = serde_json::from_str(&json).unwrap();
        assert_eq!(action, back);
    }

    #[test]
    fn risk_tags_map_as_expected() {
        assert_eq!(
            ToolAction::ScreenCapture {
                region: None,
                target_fps: 30
            }
            .risk_tag(),
            RiskTag::Low
        );
        assert_eq!(
            ToolAction::TypeText {
                text: "hello".into()
            }
            .risk_tag(),
            RiskTag::Medium
        );
        assert_eq!(
            ToolAction::BrowserNavigate {
                session_id: "s1".into(),
                url: "https://example.com".into()
            }
            .risk_tag(),
            RiskTag::High
        );
        assert_eq!(
            ToolAction::BrowserEvaluate {
                session_id: "s1".into(),
                expression: "document.title".into(),
                return_by_value: true,
            }
            .risk_tag(),
            RiskTag::High
        );
        assert_eq!(
            ToolAction::BrowserClick {
                session_id: "s1".into(),
                selector: "#submit".into(),
            }
            .risk_tag(),
            RiskTag::Medium
        );
        assert_eq!(
            ToolAction::BrowserType {
                session_id: "s1".into(),
                selector: "#q".into(),
                text: "hello".into(),
            }
            .risk_tag(),
            RiskTag::Medium
        );
        assert_eq!(
            ToolAction::BrowserProfileStart {
                session_id: "s2".into(),
                headless: false,
                url: None,
            }
            .risk_tag(),
            RiskTag::High
        );
        assert_eq!(
            ToolAction::BrowserProfileStop {
                session_id: "s2".into(),
            }
            .risk_tag(),
            RiskTag::High
        );
        assert_eq!(
            ToolAction::InputBatch {
                actions: vec![
                    InputAction::MouseMove { x: 1, y: 2 },
                    InputAction::MouseClick {
                        x: 3,
                        y: 4,
                        button: MouseButton::Left
                    }
                ],
            }
            .risk_tag(),
            RiskTag::Medium
        );
    }

    #[test]
    fn policy_action_name_is_stable() {
        let action = ToolAction::TuiInput {
            session_id: "abc".into(),
            text: "i".into(),
        };
        assert_eq!(action.policy_action_name(), "TuiInput");
    }

    #[test]
    fn browser_evaluate_defaults_return_by_value() {
        let json = r#"{"action":"browser_evaluate","session_id":"s1","expression":"1+1"}"#;
        let action: ToolAction = serde_json::from_str(json).unwrap();
        match action {
            ToolAction::BrowserEvaluate {
                return_by_value, ..
            } => assert!(return_by_value),
            other => panic!("unexpected action: {other:?}"),
        }
    }
}
