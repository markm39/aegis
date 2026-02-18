//! Message formatting and command parsing.
//!
//! Converts outbound events (alerts, pilot events) into formatted
//! [`OutboundMessage`]s and parses inbound text commands and callback
//! button presses into [`InboundAction`]s.

use aegis_alert::AlertEvent;
use aegis_control::command::Command;
use aegis_control::daemon::DaemonCommand;
use aegis_control::event::{PilotEventKind, PilotWebhookEvent};
use uuid::Uuid;

use crate::channel::{InboundAction, OutboundMessage};

/// Escape special characters for Telegram MarkdownV2.
///
/// Telegram requires escaping 18 characters: `_*[]()~>#+\-=|{}.!`
pub fn escape_md(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + s.len() / 4);
    for c in s.chars() {
        if matches!(
            c,
            '_' | '*'
                | '['
                | ']'
                | '('
                | ')'
                | '~'
                | '`'
                | '>'
                | '#'
                | '+'
                | '-'
                | '='
                | '|'
                | '{'
                | '}'
                | '.'
                | '!'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Format an alert event as an outbound Telegram message.
pub fn format_alert(event: &AlertEvent, rule_name: &str) -> OutboundMessage {
    let decision_icon = if event.decision == "Deny" {
        "DENIED"
    } else {
        "ALLOWED"
    };

    let text = format!(
        "*Alert: {}*\n\
         {}\n\n\
         *Action:* `{}`\n\
         *Principal:* `{}`\n\
         *Decision:* {}\n\
         *Reason:* {}\n\
         *Time:* {}",
        escape_md(rule_name),
        escape_md(&event.action_detail),
        escape_md(&event.action_kind),
        escape_md(&event.principal),
        escape_md(decision_icon),
        escape_md(&event.reason),
        escape_md(&event.timestamp.format("%H:%M:%S UTC").to_string()),
    );

    OutboundMessage::text(text)
}

/// Format a pilot webhook event as an outbound Telegram message.
///
/// `PendingApproval` events get inline keyboard buttons for one-tap
/// approve/deny. All other events are informational text messages.
pub fn format_pilot_event(event: &PilotWebhookEvent) -> OutboundMessage {
    match &event.kind {
        PilotEventKind::PendingApproval {
            request_id,
            raw_prompt,
        } => {
            let text = format!(
                "*Approval Required*\n\n\
                 `{}`\n\n\
                 *Agent:* `{}`\n\
                 *PID:* {}\n\
                 *ID:* `{}`",
                escape_md(raw_prompt),
                escape_md(&event.command),
                event.pid,
                escape_md(&request_id.to_string()),
            );
            let buttons = vec![
                (
                    "Approve".to_string(),
                    format!("approve:{request_id}"),
                ),
                (
                    "Deny".to_string(),
                    format!("deny:{request_id}"),
                ),
            ];
            OutboundMessage::with_buttons(text, buttons)
        }
        PilotEventKind::AttentionNeeded { nudge_count } => {
            let text = format!(
                "*Attention Needed*\n\n\
                 Agent `{}` \\(PID {}\\) has stalled after {} nudges\\.\n\
                 Manual intervention required\\.",
                escape_md(&event.command),
                event.pid,
                nudge_count,
            );
            OutboundMessage::text(text)
        }
        PilotEventKind::AgentExited { exit_code } => {
            let status = if *exit_code == 0 { "success" } else { "failure" };
            let text = format!(
                "*Agent Exited*\n\n\
                 `{}` \\(PID {}\\) exited with code {} \\({}\\)\\.\n\
                 Approved: {} \\| Denied: {} \\| Nudges: {}",
                escape_md(&event.command),
                event.pid,
                exit_code,
                escape_md(status),
                event.stats.approved,
                event.stats.denied,
                event.stats.nudges,
            );
            OutboundMessage::text(text)
        }
        PilotEventKind::StallDetected {
            nudge_count,
            idle_secs,
        } => {
            let text = format!(
                "*Stall Detected*\n\n\
                 Agent `{}` idle for {}s\\. Nudge #{} sent\\.",
                escape_md(&event.command),
                idle_secs,
                nudge_count,
            );
            OutboundMessage {
                text,
                buttons: Vec::new(),
                silent: true,
            }
        }
        PilotEventKind::PermissionApproved { action, reason } => {
            let text = format!(
                "*Permission Approved*\n\n\
                 `{}`\n\
                 Reason: {}",
                escape_md(action),
                escape_md(reason),
            );
            OutboundMessage {
                text,
                buttons: Vec::new(),
                silent: true,
            }
        }
        PilotEventKind::PermissionDenied { action, reason } => {
            let text = format!(
                "*Permission Denied*\n\n\
                 `{}`\n\
                 Reason: {}",
                escape_md(action),
                escape_md(reason),
            );
            OutboundMessage::text(text)
        }
    }
}

/// Parse a text command from the user.
///
/// Recognized commands:
/// - `/status` - get agent status
/// - `/approve <id>` - approve a pending request
/// - `/deny <id> [reason]` - deny a pending request
/// - `/output [N]` - get recent output lines
/// - `/input <text>` - send text to agent stdin
/// - `/nudge [message]` - send a nudge
/// - `/stop [message]` - request graceful shutdown
/// - `/help` - show available commands
pub fn parse_text_command(text: &str) -> InboundAction {
    let text = text.trim();

    // Strip bot mention suffix (e.g., "/status@my_bot_name")
    let (cmd, rest) = match text.split_once(' ') {
        Some((c, r)) => (c, r.trim()),
        None => (text, ""),
    };

    let cmd = cmd.split('@').next().unwrap_or(cmd);

    match cmd.to_lowercase().as_str() {
        "/status" => InboundAction::Command(Command::Status),

        "/approve" => match parse_uuid(rest) {
            Some(id) => InboundAction::Command(Command::Approve { request_id: id }),
            None => InboundAction::Unknown("Usage: /approve <request-id>".into()),
        },

        "/deny" => {
            let (id_str, reason_str) = match rest.split_once(' ') {
                Some((id, r)) => (id, Some(r.trim().to_string())),
                None => (rest, None),
            };
            match parse_uuid(id_str) {
                Some(id) => InboundAction::Command(Command::Deny {
                    request_id: id,
                    reason: reason_str,
                }),
                None => InboundAction::Unknown("Usage: /deny <request-id> [reason]".into()),
            }
        }

        "/output" => {
            let lines = if rest.is_empty() {
                None
            } else {
                rest.parse::<usize>().ok()
            };
            InboundAction::Command(Command::GetOutput { lines })
        }

        "/input" => {
            if rest.is_empty() {
                InboundAction::Unknown("Usage: /input <text>".into())
            } else {
                InboundAction::Command(Command::SendInput {
                    text: rest.to_string(),
                })
            }
        }

        "/nudge" => {
            let message = if rest.is_empty() {
                None
            } else {
                Some(rest.to_string())
            };
            InboundAction::Command(Command::Nudge { message })
        }

        "/stop" => {
            let message = if rest.is_empty() {
                None
            } else {
                Some(rest.to_string())
            };
            InboundAction::Command(Command::Shutdown { message })
        }

        "/help" => InboundAction::Unknown(String::new()),

        _ => InboundAction::Unknown(text.to_string()),
    }
}

/// Parse a callback query data string from an inline keyboard button.
///
/// Expected format: `"approve:<uuid>"` or `"deny:<uuid>"`
pub fn parse_callback(data: &str) -> Option<InboundAction> {
    let (action, id_str) = data.split_once(':')?;
    let id = Uuid::parse_str(id_str).ok()?;

    match action {
        "approve" => Some(InboundAction::Command(Command::Approve { request_id: id })),
        "deny" => Some(InboundAction::Command(Command::Deny {
            request_id: id,
            reason: None,
        })),
        _ => None,
    }
}

/// Help text sent when the user sends an unrecognized command.
pub fn help_text() -> String {
    [
        "*Aegis Commands*\n",
        "/status \\- Agent status",
        "/approve <id> \\- Approve pending request",
        "/deny <id> \\[reason\\] \\- Deny pending request",
        "/output \\[N\\] \\- Recent output lines",
        "/input <text> \\- Send text to agent",
        "/nudge \\[msg\\] \\- Nudge stalled agent",
        "/stop \\[msg\\] \\- Graceful shutdown",
        "/help \\- Show this message",
    ]
    .join("\n")
}

/// Parse a fleet-aware command from Telegram into a `DaemonCommand`.
///
/// Fleet commands include the agent name:
/// - `/status` -> list all agents
/// - `/approve <agent> <id>` -> approve a pending request
/// - `/deny <agent> <id> [reason]` -> deny a pending request
/// - `/stop <agent>` -> stop an agent
/// - `/nudge <agent> [msg]` -> nudge a stalled agent
/// - `/input <agent> <text>` -> send text to agent stdin
///
/// Returns `None` for unrecognized commands or `/help`.
pub fn parse_fleet_command(text: &str) -> Option<DaemonCommand> {
    let text = text.trim();
    let (cmd, rest) = match text.split_once(' ') {
        Some((c, r)) => (c, r.trim()),
        None => (text, ""),
    };

    let cmd = cmd.split('@').next().unwrap_or(cmd);

    match cmd.to_lowercase().as_str() {
        "/status" => Some(DaemonCommand::ListAgents),

        "/approve" => {
            let (agent, id_str) = rest.split_once(' ')?;
            let id = Uuid::parse_str(id_str.trim()).ok()?;
            Some(DaemonCommand::ApproveRequest {
                name: agent.trim().to_string(),
                request_id: id.to_string(),
            })
        }

        "/deny" => {
            let mut parts = rest.splitn(3, ' ');
            let agent = parts.next()?.trim();
            let id_str = parts.next()?.trim();
            let _id = Uuid::parse_str(id_str).ok()?;
            Some(DaemonCommand::DenyRequest {
                name: agent.to_string(),
                request_id: id_str.to_string(),
            })
        }

        "/stop" => {
            if rest.is_empty() {
                return None;
            }
            Some(DaemonCommand::StopAgent {
                name: rest.to_string(),
            })
        }

        "/nudge" => {
            let (agent, msg) = match rest.split_once(' ') {
                Some((a, m)) => (a.trim(), Some(m.trim().to_string())),
                None => {
                    if rest.is_empty() {
                        return None;
                    }
                    (rest, None)
                }
            };
            Some(DaemonCommand::NudgeAgent {
                name: agent.to_string(),
                message: msg,
            })
        }

        "/input" => {
            let (agent, text) = rest.split_once(' ')?;
            Some(DaemonCommand::SendToAgent {
                name: agent.trim().to_string(),
                text: text.trim().to_string(),
            })
        }

        "/goal" => {
            if rest.is_empty() {
                Some(DaemonCommand::FleetGoal { goal: None })
            } else {
                Some(DaemonCommand::FleetGoal { goal: Some(rest.to_string()) })
            }
        }

        "/context" => {
            if rest.is_empty() {
                return None;
            }
            let mut parts = rest.splitn(3, ' ');
            let agent = parts.next()?.trim();
            match parts.next() {
                None => {
                    // View mode: /context <agent>
                    Some(DaemonCommand::GetAgentContext { name: agent.to_string() })
                }
                Some(field) => {
                    let value = parts.next().unwrap_or("").trim().to_string();
                    let (role, agent_goal, context, task) = match field.trim() {
                        "role" => (Some(value), None, None, None),
                        "goal" => (None, Some(value), None, None),
                        "context" => (None, None, Some(value), None),
                        "task" => (None, None, None, Some(value)),
                        _ => return None,
                    };
                    Some(DaemonCommand::UpdateAgentContext {
                        name: agent.to_string(),
                        role,
                        agent_goal,
                        context,
                        task,
                    })
                }
            }
        }

        _ => None,
    }
}

/// Help text for fleet commands (Telegram MarkdownV2).
pub fn fleet_help_text() -> String {
    [
        "*Aegis Fleet Commands*\n",
        "/status \\- List all agents",
        "/approve <agent> <id> \\- Approve pending request",
        "/deny <agent> <id> \\- Deny pending request",
        "/stop <agent> \\- Stop an agent",
        "/nudge <agent> \\[msg\\] \\- Nudge stalled agent",
        "/input <agent> <text> \\- Send text to agent",
        "/goal \\- View fleet goal",
        "/goal <text> \\- Set fleet goal",
        "/context <agent> \\- View agent context",
        "/context <agent> <field> <value> \\- Set context field",
        "/help \\- Show this message",
    ]
    .join("\n")
}

fn parse_uuid(s: &str) -> Option<Uuid> {
    Uuid::parse_str(s.trim()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_control::event::EventStats;

    #[test]
    fn escape_md_special_chars() {
        assert_eq!(escape_md("hello.world"), "hello\\.world");
        assert_eq!(escape_md("a_b*c"), "a\\_b\\*c");
        assert_eq!(escape_md("no specials"), "no specials");
        assert_eq!(escape_md(""), "");
        assert_eq!(escape_md("[link](url)"), "\\[link\\]\\(url\\)");
    }

    #[test]
    fn parse_text_command_status() {
        match parse_text_command("/status") {
            InboundAction::Command(Command::Status) => {}
            other => panic!("expected Status, got {other:?}"),
        }
    }

    #[test]
    fn parse_text_command_status_with_bot_mention() {
        match parse_text_command("/status@my_aegis_bot") {
            InboundAction::Command(Command::Status) => {}
            other => panic!("expected Status, got {other:?}"),
        }
    }

    #[test]
    fn parse_text_command_approve() {
        let id = Uuid::new_v4();
        match parse_text_command(&format!("/approve {id}")) {
            InboundAction::Command(Command::Approve { request_id }) => {
                assert_eq!(request_id, id);
            }
            other => panic!("expected Approve, got {other:?}"),
        }
    }

    #[test]
    fn parse_text_command_approve_invalid_uuid() {
        match parse_text_command("/approve not-a-uuid") {
            InboundAction::Unknown(_) => {}
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn parse_text_command_deny_with_reason() {
        let id = Uuid::new_v4();
        match parse_text_command(&format!("/deny {id} too risky")) {
            InboundAction::Command(Command::Deny { request_id, reason }) => {
                assert_eq!(request_id, id);
                assert_eq!(reason, Some("too risky".to_string()));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn parse_text_command_output_default() {
        match parse_text_command("/output") {
            InboundAction::Command(Command::GetOutput { lines }) => {
                assert_eq!(lines, None);
            }
            other => panic!("expected GetOutput, got {other:?}"),
        }
    }

    #[test]
    fn parse_text_command_output_with_count() {
        match parse_text_command("/output 50") {
            InboundAction::Command(Command::GetOutput { lines }) => {
                assert_eq!(lines, Some(50));
            }
            other => panic!("expected GetOutput, got {other:?}"),
        }
    }

    #[test]
    fn parse_text_command_input() {
        match parse_text_command("/input hello world") {
            InboundAction::Command(Command::SendInput { text }) => {
                assert_eq!(text, "hello world");
            }
            other => panic!("expected SendInput, got {other:?}"),
        }
    }

    #[test]
    fn parse_text_command_input_empty() {
        match parse_text_command("/input") {
            InboundAction::Unknown(_) => {}
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn parse_text_command_nudge() {
        match parse_text_command("/nudge") {
            InboundAction::Command(Command::Nudge { message }) => {
                assert!(message.is_none());
            }
            other => panic!("expected Nudge, got {other:?}"),
        }
    }

    #[test]
    fn parse_text_command_stop() {
        match parse_text_command("/stop shutting down") {
            InboundAction::Command(Command::Shutdown { message }) => {
                assert_eq!(message, Some("shutting down".to_string()));
            }
            other => panic!("expected Shutdown, got {other:?}"),
        }
    }

    #[test]
    fn parse_text_command_help() {
        match parse_text_command("/help") {
            InboundAction::Unknown(s) => assert!(s.is_empty()),
            other => panic!("expected Unknown (help), got {other:?}"),
        }
    }

    #[test]
    fn parse_text_command_unknown() {
        match parse_text_command("random text") {
            InboundAction::Unknown(s) => assert_eq!(s, "random text"),
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn parse_callback_approve() {
        let id = Uuid::new_v4();
        let data = format!("approve:{id}");
        match parse_callback(&data) {
            Some(InboundAction::Command(Command::Approve { request_id })) => {
                assert_eq!(request_id, id);
            }
            other => panic!("expected Approve, got {other:?}"),
        }
    }

    #[test]
    fn parse_callback_deny() {
        let id = Uuid::new_v4();
        let data = format!("deny:{id}");
        match parse_callback(&data) {
            Some(InboundAction::Command(Command::Deny { request_id, .. })) => {
                assert_eq!(request_id, id);
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn parse_callback_invalid() {
        assert!(parse_callback("invalid").is_none());
        assert!(parse_callback("approve:not-uuid").is_none());
        assert!(parse_callback("unknown:00000000-0000-0000-0000-000000000000").is_none());
    }

    #[test]
    fn format_alert_deny() {
        let event = AlertEvent {
            entry_id: Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            action_kind: "FileWrite".into(),
            action_detail: r#"{"path":"/etc/passwd"}"#.into(),
            principal: "claude-agent".into(),
            decision: "Deny".into(),
            reason: "default deny".into(),
            policy_id: None,
            session_id: None,
            pilot_context: None,
        };
        let msg = format_alert(&event, "deny-secrets");
        assert!(msg.text.contains("Alert:"));
        assert!(msg.text.contains("DENIED"));
        assert!(msg.buttons.is_empty());
    }

    #[test]
    fn format_pilot_event_pending_approval() {
        let id = Uuid::new_v4();
        let event = PilotWebhookEvent::new(
            PilotEventKind::PendingApproval {
                request_id: id,
                raw_prompt: "Allow bash: rm -rf /tmp?".into(),
            },
            "claude",
            1234,
            vec![],
            None,
            EventStats::default(),
        );
        let msg = format_pilot_event(&event);
        assert!(msg.text.contains("Approval Required"));
        assert_eq!(msg.buttons.len(), 2);
        assert!(msg.buttons[0].1.starts_with("approve:"));
        assert!(msg.buttons[1].1.starts_with("deny:"));
    }

    #[test]
    fn format_pilot_event_agent_exited() {
        let event = PilotWebhookEvent::new(
            PilotEventKind::AgentExited { exit_code: 0 },
            "codex",
            5678,
            vec![],
            None,
            EventStats {
                approved: 10,
                denied: 2,
                nudges: 1,
                ..Default::default()
            },
        );
        let msg = format_pilot_event(&event);
        assert!(msg.text.contains("Agent Exited"));
        assert!(msg.text.contains("success"));
        assert!(msg.buttons.is_empty());
    }

    #[test]
    fn format_pilot_event_stall_is_silent() {
        let event = PilotWebhookEvent::new(
            PilotEventKind::StallDetected {
                nudge_count: 2,
                idle_secs: 120,
            },
            "claude",
            1234,
            vec![],
            None,
            EventStats::default(),
        );
        let msg = format_pilot_event(&event);
        assert!(msg.silent);
    }

    #[test]
    fn help_text_contains_all_commands() {
        let help = help_text();
        assert!(help.contains("/status"));
        assert!(help.contains("/approve"));
        assert!(help.contains("/deny"));
        assert!(help.contains("/output"));
        assert!(help.contains("/input"));
        assert!(help.contains("/nudge"));
        assert!(help.contains("/stop"));
        assert!(help.contains("/help"));
    }

    // Fleet command parsing tests

    #[test]
    fn fleet_status() {
        let cmd = parse_fleet_command("/status").unwrap();
        assert!(matches!(cmd, DaemonCommand::ListAgents));
    }

    #[test]
    fn fleet_approve() {
        let id = Uuid::new_v4();
        let cmd = parse_fleet_command(&format!("/approve claude-1 {id}")).unwrap();
        match cmd {
            DaemonCommand::ApproveRequest { name, request_id } => {
                assert_eq!(name, "claude-1");
                assert_eq!(request_id, id.to_string());
            }
            other => panic!("expected ApproveRequest, got {other:?}"),
        }
    }

    #[test]
    fn fleet_approve_missing_id() {
        assert!(parse_fleet_command("/approve claude-1").is_none());
    }

    #[test]
    fn fleet_approve_invalid_id() {
        assert!(parse_fleet_command("/approve claude-1 not-a-uuid").is_none());
    }

    #[test]
    fn fleet_deny() {
        let id = Uuid::new_v4();
        let cmd = parse_fleet_command(&format!("/deny agent-2 {id}")).unwrap();
        match cmd {
            DaemonCommand::DenyRequest { name, request_id } => {
                assert_eq!(name, "agent-2");
                assert_eq!(request_id, id.to_string());
            }
            other => panic!("expected DenyRequest, got {other:?}"),
        }
    }

    #[test]
    fn fleet_stop() {
        let cmd = parse_fleet_command("/stop claude-1").unwrap();
        match cmd {
            DaemonCommand::StopAgent { name } => assert_eq!(name, "claude-1"),
            other => panic!("expected StopAgent, got {other:?}"),
        }
    }

    #[test]
    fn fleet_stop_missing_agent() {
        assert!(parse_fleet_command("/stop").is_none());
    }

    #[test]
    fn fleet_nudge_with_message() {
        let cmd = parse_fleet_command("/nudge agent-1 wake up").unwrap();
        match cmd {
            DaemonCommand::NudgeAgent { name, message } => {
                assert_eq!(name, "agent-1");
                assert_eq!(message, Some("wake up".to_string()));
            }
            other => panic!("expected NudgeAgent, got {other:?}"),
        }
    }

    #[test]
    fn fleet_nudge_without_message() {
        let cmd = parse_fleet_command("/nudge agent-1").unwrap();
        match cmd {
            DaemonCommand::NudgeAgent { name, message } => {
                assert_eq!(name, "agent-1");
                assert!(message.is_none());
            }
            other => panic!("expected NudgeAgent, got {other:?}"),
        }
    }

    #[test]
    fn fleet_input() {
        let cmd = parse_fleet_command("/input claude-1 fix the bug please").unwrap();
        match cmd {
            DaemonCommand::SendToAgent { name, text } => {
                assert_eq!(name, "claude-1");
                assert_eq!(text, "fix the bug please");
            }
            other => panic!("expected SendToAgent, got {other:?}"),
        }
    }

    #[test]
    fn fleet_unknown() {
        assert!(parse_fleet_command("/bogus").is_none());
    }

    #[test]
    fn fleet_help_text_contains_commands() {
        let help = fleet_help_text();
        assert!(help.contains("/status"));
        assert!(help.contains("/approve"));
        assert!(help.contains("/stop"));
        assert!(help.contains("/nudge"));
    }
}
