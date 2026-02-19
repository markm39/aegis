//! Config-driven capability contract for orchestrator computer-use actions.
//!
//! This keeps one canonical description of what is available at runtime based
//! on `daemon.toml` (`[toolkit.*]`) so prompts and operator-facing output stay
//! aligned with policy/compliance enforcement.

use aegis_types::daemon::ToolkitConfig;

fn state(enabled: bool) -> &'static str {
    if enabled {
        "ENABLED"
    } else {
        "DISABLED"
    }
}

/// Render the orchestrator-facing capability contract.
///
/// The output is markdown-ready and intentionally explicit so an LLM can
/// reliably discover and use only configured actions.
pub fn render_orchestrator_tool_contract(
    orchestrator_name: &str,
    toolkit: &ToolkitConfig,
) -> String {
    let capture = state(toolkit.capture.enabled);
    let input = state(toolkit.input.enabled);
    let browser = state(toolkit.browser.enabled);
    let browser_backend = toolkit.browser.backend.trim();
    let browser_mode = if browser_backend.is_empty() {
        "unset"
    } else {
        browser_backend
    };
    let screenshot = if toolkit.browser.allow_screenshot {
        "ENABLED"
    } else {
        "DISABLED"
    };
    let high_risk_boundary = if toolkit.loop_executor.halt_on_high_risk {
        "ENABLED"
    } else {
        "DISABLED"
    };

    format!(
        "## Tool Capability Contract (Config Source Of Truth)\n\
         Before every UI plan, run:\n\
         - `aegis daemon capabilities {orchestrator_name}`\n\
         Treat that output as authoritative. If a capability is disabled, do not attempt it.\n\n\
         Runtime capability states from `daemon.toml`:\n\
         - Capture: `{capture}` via `[toolkit.capture.enabled]` (fps range {}..={}, default={})\n\
         - Input: `{input}` via `[toolkit.input.enabled]` (max batch actions={})\n\
         - Browser: `{browser}` via `[toolkit.browser.enabled]` (backend=`{browser_mode}`)\n\
         - Browser screenshots: `{screenshot}` via `[toolkit.browser.allow_screenshot]`\n\
         - Loop executor: max micro-actions={}, time budget={}ms, halt-on-high-risk=`{high_risk_boundary}`\n\n\
         Command patterns and canonical JSON:\n\
         - Capture stream: `aegis daemon capture-start <agent> --fps <n>`\n\
         - Latest frame: `aegis daemon latest-frame <agent>`\n\
         - TUI snapshot: `aegis daemon tool <agent> '{{\"action\":\"tui_snapshot\",\"session_id\":\"<agent-or-session>\"}}'`\n\
         - TUI input: `aegis daemon tool <agent> '{{\"action\":\"tui_input\",\"session_id\":\"<agent-or-session>\",\"text\":\"help\"}}'`\n\
         - Single action: `aegis daemon tool <agent> '{{\"action\":\"screen_capture\",\"target_fps\":30}}'`\n\
         - Input batch: `aegis daemon tool-batch <agent> '[{{\"action\":\"input_batch\",\"actions\":[{{\"kind\":\"mouse_move\",\"x\":640,\"y\":360}},{{\"kind\":\"mouse_click\",\"x\":640,\"y\":360,\"button\":\"left\"}},{{\"kind\":\"wait\",\"duration_ms\":150}}]}}]' --max-actions 3`\n\
         - Browser profile: `aegis daemon browser-profile <agent> <session_id> --headless --url https://example.com`\n\
         - Browser profile stop: `aegis daemon browser-profile-stop <agent> <session_id>`\n\
         - Browser navigate: `aegis daemon tool <agent> '{{\"action\":\"browser_navigate\",\"session_id\":\"web-1\",\"url\":\"https://example.com\"}}'`\n\
         - Browser snapshot: `aegis daemon tool <agent> '{{\"action\":\"browser_snapshot\",\"session_id\":\"web-1\",\"include_screenshot\":true}}'`\n\n\
         Runtime notes:\n\
         - For `tui_snapshot` and `tui_input`, empty `session_id` targets the current agent.\n\
         - Managed browser profiles should be explicitly stopped when no longer needed.\n\n\
         Compliance contract:\n\
         - Every computer-use action is Cedar-evaluated and may be denied.\n\
         - Fail closed: if policy/runtime path is unavailable, action is denied.\n\
         - Every action is hash-chained in the audit ledger as `RuntimeComputerUse` with typed provenance.\n\
         - High-risk actions can be halted at policy boundaries before execution."
        ,
        toolkit.capture.min_fps,
        toolkit.capture.max_fps,
        toolkit.capture.default_fps,
        toolkit.input.max_batch_actions,
        toolkit.loop_executor.max_micro_actions,
        toolkit.loop_executor.time_budget_ms
    )
}
