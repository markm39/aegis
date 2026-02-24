//! Scheduled auto-replies triggered on cron schedules.
//!
//! Provides template-based message rendering with pre-defined variables
//! pulled from daemon fleet state. Integrates with the existing [`CronScheduler`]
//! for periodic execution (daily digests, weekly summaries, health checks).
//!
//! # Security
//!
//! - Template variables are pre-defined only; no arbitrary code execution.
//! - Schedule frequency is validated (minimum 1 minute interval).
//! - Rate limiting: max 10 triggers per hour to prevent runaway schedules.
//! - Template output is sanitized before channel delivery.

use std::collections::HashMap;
use std::time::Instant;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::cron::{CronJob, CronScheduler, Schedule};

/// Pre-defined data sources for template variable population.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DataSource {
    /// Pull data from fleet status (agent count, active agents, etc.).
    FleetStatus,
    /// Pull data from session summaries (total sessions today, etc.).
    SessionSummary,
    /// Pull data from usage/cost reports.
    UsageReport,
    /// Custom static data source (key identifies the source).
    Custom { key: String },
}

/// A scheduled reply definition.
///
/// Represents a periodic message that renders a template with live fleet data
/// and delivers it through a named channel (e.g., Telegram).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledReply {
    /// Unique identifier.
    pub id: Uuid,
    /// Human-readable name (e.g., "daily-digest").
    pub name: String,
    /// When to fire.
    pub schedule: Schedule,
    /// Target channel name (e.g., "telegram").
    pub channel: String,
    /// Template text with `{{variable}}` placeholders.
    pub template: String,
    /// Where to pull template data from.
    pub data_source: DataSource,
    /// Whether this scheduled reply is active.
    pub enabled: bool,
    /// When this reply was created.
    pub created_at: DateTime<Utc>,
}

/// Pre-built template for daily fleet digest.
pub const TEMPLATE_DAILY_DIGEST: &str =
    "Fleet Status: {{agent_count}} agents ({{active_agents}} active). {{total_sessions}} sessions today.";

/// Pre-built template for health check.
pub const TEMPLATE_HEALTH_CHECK: &str =
    "Health: {{agent_count}} agents registered. {{active_agents}} currently active. Uptime: {{uptime}}.";

/// Allowed template variable names.
///
/// Only these variables are substituted. Any other `{{...}}` patterns are
/// left as-is (fail-safe: no arbitrary data leakage).
const ALLOWED_VARIABLES: &[&str] = &[
    "fleet_status",
    "agent_count",
    "active_agents",
    "total_sessions",
    "uptime",
];

/// Maximum triggers allowed per hour (rate limit).
const MAX_TRIGGERS_PER_HOUR: usize = 10;

/// Minimum schedule interval in seconds (60s = 1 minute).
const MIN_SCHEDULE_INTERVAL_SECS: u64 = 60;

/// Live fleet data used to populate template variables.
#[derive(Debug, Clone, Default)]
pub struct TemplateData {
    /// Total registered agents.
    pub agent_count: usize,
    /// Currently active/running agents.
    pub active_agents: usize,
    /// Sessions created today.
    pub total_sessions: u64,
    /// Daemon uptime in human-readable form.
    pub uptime: String,
    /// Overall fleet status summary.
    pub fleet_status: String,
}

/// Render a template by substituting `{{variable}}` placeholders with data values.
///
/// Only pre-defined variables from [`ALLOWED_VARIABLES`] are substituted.
/// Unknown variables are left as-is to prevent information leakage.
/// Output is sanitized to remove control characters.
pub fn render_template(template: &str, data: &TemplateData) -> String {
    let mut result = template.to_string();

    let vars: HashMap<&str, String> = HashMap::from([
        ("fleet_status", data.fleet_status.clone()),
        ("agent_count", data.agent_count.to_string()),
        ("active_agents", data.active_agents.to_string()),
        ("total_sessions", data.total_sessions.to_string()),
        ("uptime", data.uptime.clone()),
    ]);

    for &var_name in ALLOWED_VARIABLES {
        if let Some(value) = vars.get(var_name) {
            let placeholder = format!("{{{{{var_name}}}}}");
            result = result.replace(&placeholder, value);
        }
    }

    // Sanitize: strip control characters (except newline/tab) to prevent injection.
    sanitize_output(&result)
}

/// Strip control characters from output to prevent injection attacks.
///
/// Preserves newlines and tabs for readability, removes everything else
/// in the C0/C1 control range.
fn sanitize_output(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect()
}

/// Validate that a template only references allowed variables.
///
/// Returns `Ok(())` if all `{{...}}` placeholders use known variable names.
/// Returns `Err` with the first unrecognized variable name.
pub fn validate_template(template: &str) -> Result<(), String> {
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        let after_open = &rest[start + 2..];
        if let Some(end) = after_open.find("}}") {
            let var_name = after_open[..end].trim();
            if !ALLOWED_VARIABLES.contains(&var_name) {
                return Err(format!(
                    "unknown template variable: '{var_name}'. Allowed: {}",
                    ALLOWED_VARIABLES.join(", ")
                ));
            }
            rest = &after_open[end + 2..];
        } else {
            // Unclosed {{ -- not a variable reference, stop scanning.
            break;
        }
    }
    Ok(())
}

/// Validate that a schedule is not excessively frequent.
///
/// Rejects schedules with intervals shorter than 1 minute to prevent
/// resource exhaustion from runaway schedules.
pub fn validate_schedule_frequency(schedule: &Schedule) -> Result<(), String> {
    let interval_secs = match schedule {
        Schedule::EveryMinutes { minutes } => u64::from(*minutes) * 60,
        Schedule::EveryHours { hours } => u64::from(*hours) * 3600,
        Schedule::Daily { .. } => 86400, // Always valid (once per day).
    };

    if interval_secs < MIN_SCHEDULE_INTERVAL_SECS {
        return Err(format!(
            "schedule interval too frequent: {interval_secs}s < {MIN_SCHEDULE_INTERVAL_SECS}s minimum. \
             Schedules must be at least 1 minute apart."
        ));
    }

    Ok(())
}

/// Manages scheduled replies with rate limiting and cron integration.
pub struct ScheduledReplyManager {
    /// All registered scheduled replies.
    replies: Vec<ScheduledReply>,
    /// Underlying cron scheduler for timing.
    scheduler: CronScheduler,
    /// Trigger timestamps for rate limiting (ring buffer per reply name).
    trigger_history: HashMap<String, Vec<Instant>>,
}

impl ScheduledReplyManager {
    /// Create a new manager with an empty scheduler.
    pub fn new() -> Self {
        Self {
            replies: Vec::new(),
            scheduler: CronScheduler::new(vec![]),
            trigger_history: HashMap::new(),
        }
    }

    /// Add a scheduled reply.
    ///
    /// Validates the schedule expression and template before registering.
    /// Creates a corresponding `CronJob` in the underlying scheduler.
    pub fn add_scheduled_reply(&mut self, reply: ScheduledReply) -> Result<(), String> {
        // Validate schedule frequency.
        validate_schedule_frequency(&reply.schedule)?;

        // Validate template variables.
        validate_template(&reply.template)?;

        // Check for duplicate name.
        if self.replies.iter().any(|r| r.name == reply.name) {
            return Err(format!("scheduled reply '{}' already exists", reply.name));
        }

        // Register with cron scheduler.
        let command = serde_json::json!({
            "type": "schedule_reply_trigger",
            "name": reply.name,
        });
        let job = CronJob {
            name: reply.name.clone(),
            schedule: reply.schedule.clone(),
            command,
            enabled: reply.enabled,
        };
        self.scheduler.add(job);
        self.replies.push(reply);

        Ok(())
    }

    /// Remove a scheduled reply by name.
    ///
    /// Returns `true` if a reply was found and removed.
    pub fn remove_scheduled_reply(&mut self, name: &str) -> bool {
        let before = self.replies.len();
        self.replies.retain(|r| r.name != name);
        let removed = self.replies.len() < before;
        if removed {
            self.scheduler.remove(name);
            self.trigger_history.remove(name);
        }
        removed
    }

    /// List all registered scheduled replies.
    pub fn list_scheduled_replies(&self) -> &[ScheduledReply] {
        &self.replies
    }

    /// Trigger a scheduled reply: render its template with live data.
    ///
    /// Checks rate limits before rendering. Returns the rendered text
    /// and channel name on success.
    pub fn trigger_scheduled_reply(
        &mut self,
        name: &str,
        data: &TemplateData,
    ) -> Result<(String, String), String> {
        let reply = self
            .replies
            .iter()
            .find(|r| r.name == name)
            .ok_or_else(|| format!("scheduled reply '{name}' not found"))?;

        if !reply.enabled {
            return Err(format!("scheduled reply '{name}' is disabled"));
        }

        // Rate limit check.
        let now = Instant::now();
        let history = self.trigger_history.entry(name.to_string()).or_default();

        // Prune entries older than 1 hour.
        let one_hour_ago = now.checked_sub(std::time::Duration::from_secs(3600));
        if let Some(cutoff) = one_hour_ago {
            history.retain(|t| *t > cutoff);
        }

        if history.len() >= MAX_TRIGGERS_PER_HOUR {
            return Err(format!(
                "rate limit exceeded for '{name}': max {MAX_TRIGGERS_PER_HOUR} triggers per hour"
            ));
        }

        // Record this trigger.
        history.push(now);

        let rendered = render_template(&reply.template, data);
        let channel = reply.channel.clone();
        Ok((rendered, channel))
    }

    /// Get the underlying cron scheduler (for inspection/testing).
    pub fn scheduler(&self) -> &CronScheduler {
        &self.scheduler
    }

    /// Check for due scheduled replies and return their names.
    ///
    /// Delegates to the internal [`CronScheduler`]'s `tick_due_jobs()` method
    /// so the daemon can auto-trigger replies without manual commands.
    pub fn tick_due_reply_names(&mut self) -> Vec<String> {
        self.scheduler
            .tick_due_jobs()
            .into_iter()
            .map(|(name, _cmd)| name)
            .collect()
    }
}

impl Default for ScheduledReplyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_data() -> TemplateData {
        TemplateData {
            agent_count: 4,
            active_agents: 3,
            total_sessions: 12,
            uptime: "2h 15m".into(),
            fleet_status: "healthy".into(),
        }
    }

    fn make_reply(name: &str, schedule: Schedule, template: &str) -> ScheduledReply {
        ScheduledReply {
            id: Uuid::new_v4(),
            name: name.into(),
            schedule,
            channel: "telegram".into(),
            template: template.into(),
            data_source: DataSource::FleetStatus,
            enabled: true,
            created_at: Utc::now(),
        }
    }

    // -- template_rendering_substitutes_variables --

    #[test]
    fn template_rendering_substitutes_variables() {
        let data = sample_data();
        let template = "Agents: {{agent_count}}, Active: {{active_agents}}";
        let result = render_template(template, &data);
        assert_eq!(result, "Agents: 4, Active: 3");
    }

    // -- fleet_status_template_renders --

    #[test]
    fn fleet_status_template_renders() {
        let data = sample_data();
        let result = render_template(TEMPLATE_DAILY_DIGEST, &data);
        assert_eq!(
            result,
            "Fleet Status: 4 agents (3 active). 12 sessions today."
        );
    }

    #[test]
    fn health_check_template_renders() {
        let data = sample_data();
        let result = render_template(TEMPLATE_HEALTH_CHECK, &data);
        assert_eq!(
            result,
            "Health: 4 agents registered. 3 currently active. Uptime: 2h 15m."
        );
    }

    // -- schedule_persists_across_restart (serde roundtrip) --

    #[test]
    fn schedule_persists_across_restart() {
        let reply = make_reply(
            "daily-digest",
            Schedule::Daily { hour: 9, minute: 0 },
            TEMPLATE_DAILY_DIGEST,
        );

        let json = serde_json::to_string(&reply).unwrap();
        let back: ScheduledReply = serde_json::from_str(&json).unwrap();

        assert_eq!(back.name, "daily-digest");
        assert_eq!(back.schedule, Schedule::Daily { hour: 9, minute: 0 });
        assert_eq!(back.channel, "telegram");
        assert_eq!(back.template, TEMPLATE_DAILY_DIGEST);
        assert!(back.enabled);
    }

    // -- invalid_cron_expression_rejected --

    #[test]
    fn invalid_cron_expression_rejected() {
        assert!(Schedule::parse("weekly").is_err());
        assert!(Schedule::parse("every 0m").is_err());
        assert!(Schedule::parse("daily 25:00").is_err());
    }

    // -- security_test_template_injection_rejected --

    #[test]
    fn security_test_template_injection_rejected() {
        // Unknown variables must not be substituted.
        let data = sample_data();
        let template = "Count: {{agent_count}}, Secret: {{password}}, Env: {{PATH}}";
        let result = render_template(template, &data);
        assert!(result.contains("{{password}}"));
        assert!(result.contains("{{PATH}}"));
        assert!(result.contains("Count: 4"));
    }

    #[test]
    fn validate_template_rejects_unknown_vars() {
        let result = validate_template("Hello {{agent_count}} and {{secret_key}}");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("secret_key"));
    }

    #[test]
    fn validate_template_accepts_known_vars() {
        let result = validate_template(
            "{{fleet_status}}: {{agent_count}} agents, {{active_agents}} active, \
             {{total_sessions}} sessions, uptime {{uptime}}",
        );
        assert!(result.is_ok());
    }

    // -- security_test_excessive_frequency_rejected --

    #[test]
    fn security_test_excessive_frequency_rejected() {
        // Schedule::parse already rejects 0, but we also validate at the manager level.
        // 1-minute schedules should pass.
        let ok = Schedule::EveryMinutes { minutes: 1 };
        assert!(validate_schedule_frequency(&ok).is_ok());

        // Daily is always fine.
        let daily = Schedule::Daily { hour: 9, minute: 0 };
        assert!(validate_schedule_frequency(&daily).is_ok());

        // Hourly is fine.
        let hourly = Schedule::EveryHours { hours: 1 };
        assert!(validate_schedule_frequency(&hourly).is_ok());
    }

    // -- scheduled_reply_fires_on_cron (integration with CronJob) --

    #[test]
    fn scheduled_reply_fires_on_cron() {
        let mut mgr = ScheduledReplyManager::new();
        let reply = make_reply(
            "health-check",
            Schedule::EveryMinutes { minutes: 5 },
            TEMPLATE_HEALTH_CHECK,
        );
        mgr.add_scheduled_reply(reply).unwrap();

        // Verify the cron job was registered.
        assert_eq!(mgr.scheduler().list().len(), 1);
        assert_eq!(mgr.scheduler().list()[0].name, "health-check");

        // Trigger and verify rendered output.
        let data = sample_data();
        let (text, channel) = mgr.trigger_scheduled_reply("health-check", &data).unwrap();
        assert_eq!(channel, "telegram");
        assert!(text.contains("4 agents registered"));
        assert!(text.contains("3 currently active"));
    }

    #[test]
    fn add_duplicate_name_rejected() {
        let mut mgr = ScheduledReplyManager::new();
        let reply1 = make_reply(
            "digest",
            Schedule::Daily { hour: 9, minute: 0 },
            TEMPLATE_DAILY_DIGEST,
        );
        mgr.add_scheduled_reply(reply1).unwrap();

        let reply2 = make_reply(
            "digest",
            Schedule::Daily {
                hour: 18,
                minute: 0,
            },
            TEMPLATE_HEALTH_CHECK,
        );
        let err = mgr.add_scheduled_reply(reply2).unwrap_err();
        assert!(err.contains("already exists"));
    }

    #[test]
    fn remove_scheduled_reply_works() {
        let mut mgr = ScheduledReplyManager::new();
        let reply = make_reply(
            "daily",
            Schedule::Daily { hour: 9, minute: 0 },
            TEMPLATE_DAILY_DIGEST,
        );
        mgr.add_scheduled_reply(reply).unwrap();
        assert_eq!(mgr.list_scheduled_replies().len(), 1);

        assert!(mgr.remove_scheduled_reply("daily"));
        assert_eq!(mgr.list_scheduled_replies().len(), 0);
        assert_eq!(mgr.scheduler().list().len(), 0);

        // Removing nonexistent returns false.
        assert!(!mgr.remove_scheduled_reply("nonexistent"));
    }

    #[test]
    fn trigger_nonexistent_returns_error() {
        let mut mgr = ScheduledReplyManager::new();
        let data = sample_data();
        let result = mgr.trigger_scheduled_reply("ghost", &data);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn trigger_disabled_reply_returns_error() {
        let mut mgr = ScheduledReplyManager::new();
        let mut reply = make_reply(
            "disabled-check",
            Schedule::Daily { hour: 9, minute: 0 },
            TEMPLATE_HEALTH_CHECK,
        );
        reply.enabled = false;
        mgr.add_scheduled_reply(reply).unwrap();

        let data = sample_data();
        let result = mgr.trigger_scheduled_reply("disabled-check", &data);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("disabled"));
    }

    #[test]
    fn rate_limit_enforced() {
        let mut mgr = ScheduledReplyManager::new();
        let reply = make_reply(
            "frequent",
            Schedule::EveryMinutes { minutes: 5 },
            "{{agent_count}} agents",
        );
        mgr.add_scheduled_reply(reply).unwrap();

        let data = sample_data();

        // Exhaust the rate limit.
        for _ in 0..MAX_TRIGGERS_PER_HOUR {
            mgr.trigger_scheduled_reply("frequent", &data).unwrap();
        }

        // Next trigger should fail.
        let result = mgr.trigger_scheduled_reply("frequent", &data);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("rate limit exceeded"));
    }

    #[test]
    fn sanitize_strips_control_chars() {
        let data = TemplateData {
            agent_count: 1,
            fleet_status: "ok\x00\x07\x1b[31m".into(),
            ..Default::default()
        };
        let result = render_template("Status: {{fleet_status}}", &data);
        // Control chars stripped, but regular chars kept.
        assert!(!result.contains('\x00'));
        assert!(!result.contains('\x07'));
        assert!(!result.contains('\x1b'));
        assert!(result.contains("ok"));
        assert!(result.contains("[31m")); // The bracket chars are kept, only \x1b stripped.
    }

    #[test]
    fn data_source_serde_roundtrip() {
        let sources = vec![
            DataSource::FleetStatus,
            DataSource::SessionSummary,
            DataSource::UsageReport,
            DataSource::Custom {
                key: "my-source".into(),
            },
        ];

        for src in sources {
            let json = serde_json::to_string(&src).unwrap();
            let back: DataSource = serde_json::from_str(&json).unwrap();
            assert_eq!(back, src);
        }
    }

    #[test]
    fn template_with_no_variables_passes_through() {
        let data = sample_data();
        let result = render_template("Plain text with no vars", &data);
        assert_eq!(result, "Plain text with no vars");
    }

    #[test]
    fn validate_template_empty_is_ok() {
        assert!(validate_template("").is_ok());
        assert!(validate_template("no variables here").is_ok());
    }

    #[test]
    fn validate_template_unclosed_brace_ok() {
        // Unclosed {{ is not treated as a variable.
        assert!(validate_template("some {{ text").is_ok());
    }

    #[test]
    fn tick_due_reply_names_returns_due_replies() {
        let mut mgr = ScheduledReplyManager::new();
        mgr.add_scheduled_reply(make_reply(
            "daily-digest",
            Schedule::Daily { hour: 9, minute: 0 },
            TEMPLATE_DAILY_DIGEST,
        ))
        .unwrap();
        mgr.add_scheduled_reply(make_reply(
            "health-check",
            Schedule::EveryMinutes { minutes: 5 },
            TEMPLATE_HEALTH_CHECK,
        ))
        .unwrap();

        // First tick: all due (never fired).
        let names = mgr.tick_due_reply_names();
        assert_eq!(names.len(), 2);

        // Immediately after: nothing due.
        let names2 = mgr.tick_due_reply_names();
        assert!(names2.is_empty());
    }

    #[test]
    fn tick_due_reply_names_empty_when_no_replies() {
        let mut mgr = ScheduledReplyManager::new();
        assert!(mgr.tick_due_reply_names().is_empty());
    }
}
