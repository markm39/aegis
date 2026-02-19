//! Cedar mapping helpers for computer-use actions.

use serde::{Deserialize, Serialize};

use crate::contract::{RiskTag, ToolAction};

/// Normalized policy metadata derived from a tool action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CedarActionMetadata {
    /// Stable Cedar action name.
    pub cedar_action: &'static str,
    /// Risk tag used for policy/approval routing.
    pub risk_tag: RiskTag,
    /// Whether the action should default to explicit approval.
    pub requires_explicit_approval: bool,
}

/// Map a tool action to Cedar policy metadata.
pub fn map_tool_action(action: &ToolAction) -> CedarActionMetadata {
    let risk_tag = action.risk_tag();
    CedarActionMetadata {
        cedar_action: action.policy_action_name(),
        risk_tag,
        requires_explicit_approval: matches!(risk_tag, RiskTag::High),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::MouseButton;

    #[test]
    fn map_tool_action_low_risk() {
        let action = ToolAction::ScreenCapture {
            region: None,
            target_fps: 30,
        };
        let meta = map_tool_action(&action);
        assert_eq!(meta.cedar_action, "ScreenCapture");
        assert_eq!(meta.risk_tag, RiskTag::Low);
        assert!(!meta.requires_explicit_approval);
    }

    #[test]
    fn map_tool_action_high_risk_requires_approval() {
        let action = ToolAction::BrowserNavigate {
            session_id: "b1".into(),
            url: "https://example.com".into(),
        };
        let meta = map_tool_action(&action);
        assert_eq!(meta.cedar_action, "BrowserNavigate");
        assert_eq!(meta.risk_tag, RiskTag::High);
        assert!(meta.requires_explicit_approval);
    }

    #[test]
    fn map_tool_action_medium_risk() {
        let action = ToolAction::MouseClick {
            x: 1,
            y: 2,
            button: MouseButton::Left,
        };
        let meta = map_tool_action(&action);
        assert_eq!(meta.cedar_action, "MouseClick");
        assert_eq!(meta.risk_tag, RiskTag::Medium);
        assert!(!meta.requires_explicit_approval);
    }
}
