//! Lightweight job scheduler for periodic daemon tasks.
//!
//! Supports simple scheduling expressions: "every Nm" (minutes),
//! "every Nh" (hours), "daily HH:MM". Jobs execute DaemonCommands.

use std::time::Duration;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

/// A scheduling interval for a cron job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Schedule {
    /// Run every N minutes.
    EveryMinutes { minutes: u32 },
    /// Run every N hours.
    EveryHours { hours: u32 },
    /// Run once daily at a specific time (UTC).
    Daily { hour: u8, minute: u8 },
}

impl Schedule {
    /// Parse a human-readable schedule string.
    ///
    /// Supported formats:
    /// - `"every 5m"` -- every 5 minutes
    /// - `"every 2h"` -- every 2 hours
    /// - `"daily 09:30"` -- daily at 09:30 UTC
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();

        if let Some(rest) = s.strip_prefix("every ") {
            let rest = rest.trim();
            if let Some(mins) = rest.strip_suffix('m') {
                let n: u32 = mins
                    .trim()
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invalid minutes value: {mins}"))?;
                if n == 0 {
                    bail!("minutes must be > 0");
                }
                return Ok(Schedule::EveryMinutes { minutes: n });
            }
            if let Some(hours) = rest.strip_suffix('h') {
                let n: u32 = hours
                    .trim()
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invalid hours value: {hours}"))?;
                if n == 0 {
                    bail!("hours must be > 0");
                }
                return Ok(Schedule::EveryHours { hours: n });
            }
            bail!("invalid schedule interval: expected 'every Nm' or 'every Nh', got: {s}");
        }

        if let Some(time_str) = s.strip_prefix("daily ") {
            let time_str = time_str.trim();
            let parts: Vec<&str> = time_str.split(':').collect();
            if parts.len() != 2 {
                bail!("invalid daily time format: expected HH:MM, got: {time_str}");
            }
            let hour: u8 = parts[0]
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid hour: {}", parts[0]))?;
            let minute: u8 = parts[1]
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid minute: {}", parts[1]))?;
            if hour >= 24 {
                bail!("hour must be 0-23, got: {hour}");
            }
            if minute >= 60 {
                bail!("minute must be 0-59, got: {minute}");
            }
            return Ok(Schedule::Daily { hour, minute });
        }

        bail!(
            "unrecognized schedule format: {s} (expected 'every Nm', 'every Nh', or 'daily HH:MM')"
        );
    }

    /// Duration until the next tick for interval-based schedules.
    ///
    /// For `EveryMinutes` and `EveryHours`, returns the fixed interval duration.
    /// For `Daily`, returns the time remaining until the next occurrence of the
    /// specified time (UTC).
    pub fn next_tick_duration(&self) -> Duration {
        match self {
            Schedule::EveryMinutes { minutes } => Duration::from_secs(u64::from(*minutes) * 60),
            Schedule::EveryHours { hours } => Duration::from_secs(u64::from(*hours) * 3600),
            Schedule::Daily { hour, minute } => {
                let now = chrono::Utc::now();
                let today = now.date_naive();
                let target_time =
                    chrono::NaiveTime::from_hms_opt(u32::from(*hour), u32::from(*minute), 0)
                        .expect("valid time from validated hour/minute");
                let target_dt = today.and_time(target_time);
                let target_utc = target_dt.and_utc();

                if target_utc > now {
                    (target_utc - now)
                        .to_std()
                        .unwrap_or(Duration::from_secs(1))
                } else {
                    // Already past today's time; schedule for tomorrow.
                    let tomorrow = today
                        .succ_opt()
                        .expect("valid next day")
                        .and_time(target_time)
                        .and_utc();
                    (tomorrow - now).to_std().unwrap_or(Duration::from_secs(1))
                }
            }
        }
    }
}

/// A scheduled job that maps to a DaemonCommand.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronJob {
    /// Unique job name.
    pub name: String,
    /// When to run.
    pub schedule: Schedule,
    /// Serialized DaemonCommand to execute.
    pub command: serde_json::Value,
    /// Whether this job is active.
    pub enabled: bool,
}

/// Registry of scheduled jobs.
pub struct CronScheduler {
    jobs: Vec<CronJob>,
}

impl CronScheduler {
    /// Create a new scheduler with the given initial jobs.
    pub fn new(jobs: Vec<CronJob>) -> Self {
        Self { jobs }
    }

    /// Add a job to the scheduler.
    pub fn add(&mut self, job: CronJob) {
        self.jobs.push(job);
    }

    /// Remove a job by name. Returns `true` if a job was removed.
    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.jobs.len();
        self.jobs.retain(|j| j.name != name);
        self.jobs.len() < before
    }

    /// List all registered jobs.
    pub fn list(&self) -> &[CronJob] {
        &self.jobs
    }

    /// Look up a job by name and return its command for execution.
    /// Returns `None` if the job does not exist.
    pub fn trigger(&self, name: &str) -> Option<&serde_json::Value> {
        self.jobs
            .iter()
            .find(|j| j.name == name)
            .map(|j| &j.command)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_every_minutes() {
        let s = Schedule::parse("every 5m").unwrap();
        assert_eq!(s, Schedule::EveryMinutes { minutes: 5 });
    }

    #[test]
    fn parse_every_hours() {
        let s = Schedule::parse("every 2h").unwrap();
        assert_eq!(s, Schedule::EveryHours { hours: 2 });
    }

    #[test]
    fn parse_daily() {
        let s = Schedule::parse("daily 09:30").unwrap();
        assert_eq!(
            s,
            Schedule::Daily {
                hour: 9,
                minute: 30
            }
        );
    }

    #[test]
    fn parse_daily_midnight() {
        let s = Schedule::parse("daily 00:00").unwrap();
        assert_eq!(s, Schedule::Daily { hour: 0, minute: 0 });
    }

    #[test]
    fn parse_invalid_formats() {
        assert!(Schedule::parse("every 0m").is_err());
        assert!(Schedule::parse("every 0h").is_err());
        assert!(Schedule::parse("daily 25:00").is_err());
        assert!(Schedule::parse("daily 12:60").is_err());
        assert!(Schedule::parse("weekly").is_err());
        assert!(Schedule::parse("every xm").is_err());
        assert!(Schedule::parse("daily bad").is_err());
    }

    #[test]
    fn next_tick_duration_minutes() {
        let s = Schedule::EveryMinutes { minutes: 5 };
        assert_eq!(s.next_tick_duration(), Duration::from_secs(300));
    }

    #[test]
    fn next_tick_duration_hours() {
        let s = Schedule::EveryHours { hours: 2 };
        assert_eq!(s.next_tick_duration(), Duration::from_secs(7200));
    }

    #[test]
    fn next_tick_duration_daily_is_within_24h() {
        let s = Schedule::Daily {
            hour: 12,
            minute: 0,
        };
        let dur = s.next_tick_duration();
        // Should always be <= 24 hours.
        assert!(dur <= Duration::from_secs(24 * 3600));
        // Should always be > 0.
        assert!(dur > Duration::ZERO);
    }

    #[test]
    fn scheduler_add_remove_list() {
        let mut scheduler = CronScheduler::new(vec![]);
        assert_eq!(scheduler.list().len(), 0);

        scheduler.add(CronJob {
            name: "job1".into(),
            schedule: Schedule::EveryMinutes { minutes: 1 },
            command: serde_json::json!({"type": "ping"}),
            enabled: true,
        });
        assert_eq!(scheduler.list().len(), 1);

        scheduler.add(CronJob {
            name: "job2".into(),
            schedule: Schedule::EveryHours { hours: 1 },
            command: serde_json::json!({"type": "list_agents"}),
            enabled: true,
        });
        assert_eq!(scheduler.list().len(), 2);

        assert!(scheduler.remove("job1"));
        assert_eq!(scheduler.list().len(), 1);
        assert_eq!(scheduler.list()[0].name, "job2");

        // Removing nonexistent job returns false.
        assert!(!scheduler.remove("job1"));
    }

    #[test]
    fn scheduler_trigger() {
        let mut scheduler = CronScheduler::new(vec![]);
        scheduler.add(CronJob {
            name: "ping-job".into(),
            schedule: Schedule::EveryMinutes { minutes: 5 },
            command: serde_json::json!({"type": "ping"}),
            enabled: true,
        });

        let cmd = scheduler.trigger("ping-job");
        assert!(cmd.is_some());
        assert_eq!(cmd.unwrap(), &serde_json::json!({"type": "ping"}));

        assert!(scheduler.trigger("nonexistent").is_none());
    }

    #[test]
    fn parse_with_whitespace() {
        let s = Schedule::parse("  every  10m  ").unwrap();
        assert_eq!(s, Schedule::EveryMinutes { minutes: 10 });
    }

    #[test]
    fn schedule_json_roundtrip() {
        let schedules = vec![
            Schedule::EveryMinutes { minutes: 15 },
            Schedule::EveryHours { hours: 6 },
            Schedule::Daily { hour: 8, minute: 0 },
        ];

        for sched in schedules {
            let json = serde_json::to_string(&sched).unwrap();
            let back: Schedule = serde_json::from_str(&json).unwrap();
            assert_eq!(back, sched);
        }
    }
}
