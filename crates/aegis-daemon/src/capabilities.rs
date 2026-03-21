//! Runtime capability introspection and tool auth readiness checks.

use aegis_control::daemon::RuntimeCapabilities;
use aegis_control::hooks;
use aegis_types::daemon::{AgentSlotConfig, AgentToolConfig};

pub(crate) fn env_present(var: &str) -> bool {
    std::env::var(var)
        .ok()
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
}

/// Compute runtime capability and policy-mediation coverage for an agent slot.
pub(crate) fn runtime_capabilities(config: &AgentSlotConfig) -> RuntimeCapabilities {
    let (
        tool,
        headless,
        policy_mediation,
        mediation_note,
        mediation_mode,
        hook_bridge,
        tool_coverage,
        compliance_mode,
    ) = match &config.tool {
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
        AgentToolConfig::Codex { runtime_engine, .. } => {
            let note = if runtime_engine != "external" {
                "native coding runtime enabled; external codex fallback allowed, policy mediation remains partial until secure bridge is available"
                    .to_string()
            } else {
                "external codex runtime enabled; policy mediation is partial until secure bridge is available"
                    .to_string()
            };
            (
                "Codex".to_string(),
                true,
                "partial".to_string(),
                note,
                "partial".to_string(),
                "unavailable".to_string(),
                "partial".to_string(),
                "advisory".to_string(),
            )
        }
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
        name: config.name.to_string(),
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

pub(crate) fn tool_auth_readiness(config: &AgentSlotConfig) -> (String, bool, String) {
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
