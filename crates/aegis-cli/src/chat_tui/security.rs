//! Security posture state for the chat TUI.
//!
//! [`SecurityPosture`] aggregates the current security configuration into a
//! single struct that the TUI polls from the daemon. It feeds the status bar
//! rendered by [`super::render::render_status_bar`] and provides verdict
//! information for tool call badges.

/// Security posture state, polled from the daemon.
///
/// Combines policy mode, sandbox status, audit chain health, and the most
/// recent tool evaluation result into a single snapshot used by the chat TUI
/// rendering layer.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct SecurityPosture {
    /// Policy evaluation mode: "strict", "permissive", "learning".
    pub policy_mode: String,
    /// Mediation mode from RuntimeCapabilities (e.g. "enforced", "advisory").
    pub mediation_mode: String,
    /// Whether the Seatbelt sandbox is active for the current agent.
    pub sandbox_active: bool,
    /// Total number of entries in the audit ledger.
    pub audit_entries: u64,
    /// Whether the hash chain in the audit ledger is intact.
    pub audit_chain_ok: bool,
    /// Last tool action name (from RuntimeCapabilities).
    pub last_tool_action: Option<String>,
    /// Last tool evaluation decision ("allow", "deny", "ask").
    pub last_tool_decision: Option<String>,
    /// Last tool risk tag (e.g. "low", "medium", "high").
    pub last_tool_risk: Option<String>,
}

#[allow(dead_code)]
impl SecurityPosture {
    /// Create a new posture with safe defaults.
    ///
    /// Starts with strict policy, unknown mediation, no sandbox, and a
    /// healthy (empty) audit chain.
    pub fn new() -> Self {
        Self {
            policy_mode: "strict".to_string(),
            mediation_mode: "unknown".to_string(),
            sandbox_active: false,
            audit_entries: 0,
            audit_chain_ok: true,
            last_tool_action: None,
            last_tool_decision: None,
            last_tool_risk: None,
        }
    }

    /// Update fields from a RuntimeCapabilities JSON response.
    ///
    /// Expected keys:
    /// - `mediation_mode` (string)
    /// - `last_tool_action` (string)
    /// - `last_tool_decision` (string)
    /// - `last_tool_risk_tag` (string)
    ///
    /// Sandbox and audit fields come from other sources and are not updated
    /// here.
    pub fn update_from_capabilities(&mut self, caps: &serde_json::Value) {
        if let Some(m) = caps["mediation_mode"].as_str() {
            self.mediation_mode = m.to_string();
        }
        if let Some(action) = caps["last_tool_action"].as_str() {
            self.last_tool_action = Some(action.to_string());
        }
        if let Some(decision) = caps["last_tool_decision"].as_str() {
            self.last_tool_decision = Some(decision.to_string());
        }
        if let Some(risk) = caps["last_tool_risk_tag"].as_str() {
            self.last_tool_risk = Some(risk.to_string());
        }
    }

    /// Update the audit ledger stats.
    pub fn update_audit(&mut self, entry_count: u64, chain_ok: bool) {
        self.audit_entries = entry_count;
        self.audit_chain_ok = chain_ok;
    }

    /// Get the verdict string for the most recent tool call, if any.
    pub fn last_verdict(&self) -> Option<&str> {
        self.last_tool_decision.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_posture_defaults() {
        let sp = SecurityPosture::new();
        assert_eq!(sp.policy_mode, "strict");
        assert_eq!(sp.mediation_mode, "unknown");
        assert!(!sp.sandbox_active);
        assert_eq!(sp.audit_entries, 0);
        assert!(sp.audit_chain_ok);
        assert!(sp.last_tool_action.is_none());
        assert!(sp.last_tool_decision.is_none());
        assert!(sp.last_tool_risk.is_none());
    }

    #[test]
    fn security_posture_default_trait() {
        let sp = SecurityPosture::default();
        // Derived Default gives empty strings, not "strict"/"unknown".
        assert_eq!(sp.policy_mode, "");
        assert_eq!(sp.mediation_mode, "");
        // bool default is false, unlike SecurityPosture::new() which sets true.
        assert!(!sp.audit_chain_ok);
    }

    #[test]
    fn security_posture_update_from_caps() {
        let mut sp = SecurityPosture::new();
        let caps = serde_json::json!({
            "mediation_mode": "enforced",
            "last_tool_action": "Bash",
            "last_tool_decision": "allow",
            "last_tool_risk_tag": "medium"
        });
        sp.update_from_capabilities(&caps);
        assert_eq!(sp.mediation_mode, "enforced");
        assert_eq!(sp.last_tool_action.as_deref(), Some("Bash"));
        assert_eq!(sp.last_tool_decision.as_deref(), Some("allow"));
        assert_eq!(sp.last_tool_risk.as_deref(), Some("medium"));
        assert_eq!(sp.last_verdict(), Some("allow"));
    }

    #[test]
    fn security_posture_update_partial_caps() {
        let mut sp = SecurityPosture::new();
        let caps = serde_json::json!({
            "mediation_mode": "advisory"
        });
        sp.update_from_capabilities(&caps);
        assert_eq!(sp.mediation_mode, "advisory");
        // Other fields unchanged.
        assert!(sp.last_tool_action.is_none());
        assert!(sp.last_tool_decision.is_none());
        assert!(sp.last_tool_risk.is_none());
    }

    #[test]
    fn security_posture_update_empty_caps() {
        let mut sp = SecurityPosture::new();
        let caps = serde_json::json!({});
        sp.update_from_capabilities(&caps);
        // Nothing should change.
        assert_eq!(sp.mediation_mode, "unknown");
        assert!(sp.last_tool_action.is_none());
    }

    #[test]
    fn security_posture_update_audit() {
        let mut sp = SecurityPosture::new();
        assert_eq!(sp.audit_entries, 0);
        assert!(sp.audit_chain_ok);

        sp.update_audit(500, true);
        assert_eq!(sp.audit_entries, 500);
        assert!(sp.audit_chain_ok);

        sp.update_audit(501, false);
        assert_eq!(sp.audit_entries, 501);
        assert!(!sp.audit_chain_ok);
    }

    #[test]
    fn security_posture_last_verdict_none() {
        let sp = SecurityPosture::new();
        assert_eq!(sp.last_verdict(), None);
    }

    #[test]
    fn security_posture_last_verdict_deny() {
        let mut sp = SecurityPosture::new();
        sp.last_tool_decision = Some("deny".to_string());
        assert_eq!(sp.last_verdict(), Some("deny"));
    }

    #[test]
    fn security_posture_sandbox_toggle() {
        let mut sp = SecurityPosture::new();
        assert!(!sp.sandbox_active);
        sp.sandbox_active = true;
        assert!(sp.sandbox_active);
    }
}
