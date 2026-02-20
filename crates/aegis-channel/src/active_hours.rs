//! Active hours gating for outbound notifications.

use chrono::{DateTime, Local, Timelike, Utc};
use chrono_tz::Tz;
use regex::Regex;

use aegis_types::ActiveHoursConfig;

const TIME_PATTERN: &str = r"^(?:([01]\d|2[0-3]):([0-5]\d)|24:00)$";

fn parse_time_minutes(raw: &str, allow_24: bool) -> Option<u32> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if !Regex::new(TIME_PATTERN).ok()?.is_match(raw) {
        return None;
    }
    let mut parts = raw.split(':');
    let hour: u32 = parts.next()?.parse().ok()?;
    let minute: u32 = parts.next()?.parse().ok()?;
    if hour == 24 {
        if !allow_24 || minute != 0 {
            return None;
        }
        return Some(24 * 60);
    }
    Some(hour * 60 + minute)
}

fn resolve_timezone(raw: Option<&str>) -> TimeZoneChoice {
    match raw.map(|s| s.trim().to_lowercase()) {
        None => TimeZoneChoice::Local,
        Some(ref v) if v.is_empty() => TimeZoneChoice::Local,
        Some(ref v) if v == "user" || v == "local" => TimeZoneChoice::Local,
        Some(v) => match v.parse::<Tz>() {
            Ok(tz) => TimeZoneChoice::Named(tz),
            Err(_) => TimeZoneChoice::Local,
        },
    }
}

enum TimeZoneChoice {
    Local,
    Named(Tz),
}

fn minutes_in_timezone(now: DateTime<Utc>, tz: TimeZoneChoice) -> Option<u32> {
    match tz {
        TimeZoneChoice::Local => {
            let local = now.with_timezone(&Local);
            Some(local.hour() * 60 + local.minute())
        }
        TimeZoneChoice::Named(tz) => {
            let local = now.with_timezone(&tz);
            Some(local.hour() * 60 + local.minute())
        }
    }
}

/// Returns true if the current time is within the configured active hours.
///
/// Invalid or incomplete configuration defaults to "allow".
pub fn within_active_hours(cfg: Option<&ActiveHoursConfig>, now: DateTime<Utc>) -> bool {
    let Some(active) = cfg else {
        return true;
    };

    let start = parse_time_minutes(&active.start, false);
    let end = parse_time_minutes(&active.end, true);
    let (Some(start), Some(end)) = (start, end) else {
        return true;
    };
    if start == end {
        return false;
    }

    let tz = resolve_timezone(active.timezone.as_deref());
    let current = match minutes_in_timezone(now, tz) {
        Some(v) => v,
        None => return true,
    };

    if end > start {
        current >= start && current < end
    } else {
        current >= start || current < end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inactive_when_start_equals_end() {
        let cfg = ActiveHoursConfig {
            start: "09:00".into(),
            end: "09:00".into(),
            timezone: Some("UTC".into()),
        };
        let now = DateTime::<Utc>::from_timestamp(0, 0).unwrap();
        assert!(!within_active_hours(Some(&cfg), now));
    }
}
