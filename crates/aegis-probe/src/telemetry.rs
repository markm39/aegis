//! Opt-in anonymized telemetry for aggregate security intelligence.
//!
//! Telemetry is **disabled by default**. Enable with `--telemetry` or `AEGIS_TELEMETRY=1`.
//!
//! What we collect (all anonymized):
//! - Probe name, category, severity, verdict, duration
//! - Agent type (e.g. "ClaudeCode", never the binary path)
//! - Anonymized system fingerprint (SHA-256 of hostname + OS + arch)
//! - Timestamp
//!
//! What we never collect:
//! - Agent output or prompts
//! - File contents or paths from the user's system
//! - API keys, tokens, or credentials
//! - IP addresses or hostnames

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::scoring::{ProbeResult, SecurityReport};

/// A single anonymized telemetry event from a probe run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    /// Schema version for forward compatibility.
    pub schema_version: u8,
    /// Anonymized system fingerprint.
    pub system_id: String,
    /// Agent type being tested.
    pub agent: String,
    /// Probe name.
    pub probe_name: String,
    /// Attack category.
    pub category: String,
    /// Configured severity.
    pub severity: String,
    /// Test verdict.
    pub verdict: String,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Number of findings.
    pub finding_count: usize,
    /// Whether the agent refused the attack.
    pub agent_refused: bool,
    /// ISO 8601 timestamp.
    pub timestamp: String,
}

/// Generate an anonymized system fingerprint.
///
/// Uses SHA-256 of hostname + OS + arch, truncated to 16 hex chars.
/// This identifies a unique system without revealing any identifying info.
fn system_fingerprint() -> String {
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_default();

    let mut hasher = Sha256::new();
    hasher.update(hostname.as_bytes());
    hasher.update(std::env::consts::OS.as_bytes());
    hasher.update(std::env::consts::ARCH.as_bytes());

    let hash = hasher.finalize();
    hex::encode(&hash[..8])
}

/// Convert a probe result into an anonymized telemetry event.
pub fn result_to_event(result: &ProbeResult) -> TelemetryEvent {
    let agent_refused = result
        .findings
        .iter()
        .any(|f| matches!(f.kind, crate::scoring::FindingKind::AgentRefused));

    TelemetryEvent {
        schema_version: 1,
        system_id: system_fingerprint(),
        agent: result.agent.clone(),
        probe_name: result.probe_name.clone(),
        category: format!("{:?}", result.category),
        severity: format!("{:?}", result.severity),
        verdict: format!("{:?}", result.verdict),
        duration_ms: result.duration_ms,
        finding_count: result.findings.len(),
        agent_refused,
        timestamp: result.timestamp.to_rfc3339(),
    }
}

/// Default telemetry file path: ~/.aegis/telemetry.jsonl
pub fn default_telemetry_path() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".aegis").join("telemetry.jsonl")
}

/// Check if telemetry is enabled via environment variable.
pub fn is_enabled() -> bool {
    std::env::var("AEGIS_TELEMETRY")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Record telemetry events from a security report.
///
/// Appends anonymized JSONL events to ~/.aegis/telemetry.jsonl.
/// Silently does nothing if telemetry is disabled or if writing fails.
pub fn record_report(report: &SecurityReport) {
    if !is_enabled() {
        return;
    }

    let path = default_telemetry_path();

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let mut file = match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(f) => f,
        Err(_) => return,
    };

    for result in &report.results {
        let event = result_to_event(result);
        if let Ok(json) = serde_json::to_string(&event) {
            let _ = writeln!(file, "{json}");
        }
    }
}

/// Remote telemetry endpoint configuration.
///
/// Set `AEGIS_TELEMETRY_URL` to an InfluxDB v2 write endpoint to enable remote export.
/// Set `AEGIS_TELEMETRY_TOKEN` for authentication (optional, depends on endpoint config).
///
/// Example:
///   AEGIS_TELEMETRY_URL=https://eu-central-1-1.aws.cloud2.influxdata.com/api/v2/write?org=aegis&bucket=probes
///   AEGIS_TELEMETRY_TOKEN=your-influxdb-token
pub struct RemoteConfig {
    pub url: String,
    pub token: Option<String>,
}

/// Get remote telemetry config from environment, if set.
pub fn remote_config() -> Option<RemoteConfig> {
    let url = std::env::var("AEGIS_TELEMETRY_URL").ok()?;
    let token = std::env::var("AEGIS_TELEMETRY_TOKEN").ok();
    Some(RemoteConfig { url, token })
}

/// Convert a telemetry event to InfluxDB line protocol format.
///
/// Format: `measurement,tag=value field=value timestamp_ns`
fn event_to_line_protocol(event: &TelemetryEvent) -> String {
    // Tags (indexed, low cardinality)
    let tags = format!(
        "agent={},category={},severity={},verdict={},system_id={}",
        escape_tag(&event.agent),
        escape_tag(&event.category),
        escape_tag(&event.severity),
        escape_tag(&event.verdict),
        escape_tag(&event.system_id),
    );

    // Fields (values)
    let fields = format!(
        "probe_name=\"{}\",duration_ms={}u,finding_count={}u,agent_refused={},schema_version={}u",
        escape_field_str(&event.probe_name),
        event.duration_ms,
        event.finding_count,
        event.agent_refused,
        event.schema_version,
    );

    // Timestamp: parse ISO 8601 to nanoseconds, fallback to current time
    let timestamp_ns = chrono::DateTime::parse_from_rfc3339(&event.timestamp)
        .map(|dt| dt.timestamp_nanos_opt().unwrap_or(0))
        .unwrap_or_else(|_| chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0));

    format!("aegis_probe,{tags} {fields} {timestamp_ns}")
}

/// Escape tag key/value for InfluxDB line protocol.
fn escape_tag(s: &str) -> String {
    s.replace(',', "\\,")
        .replace('=', "\\=")
        .replace(' ', "\\ ")
}

/// Escape a string field value for InfluxDB line protocol.
fn escape_field_str(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Push telemetry events to a remote InfluxDB endpoint.
///
/// Returns the number of events successfully sent, or an error.
pub fn push_remote(events: &[TelemetryEvent], config: &RemoteConfig) -> Result<usize, String> {
    if events.is_empty() {
        return Ok(0);
    }

    let body: String = events
        .iter()
        .map(event_to_line_protocol)
        .collect::<Vec<_>>()
        .join("\n");

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("HTTP client error: {e}"))?;

    let mut request = client
        .post(&config.url)
        .header("Content-Type", "text/plain; charset=utf-8")
        .body(body);

    if let Some(ref token) = config.token {
        request = request.header("Authorization", format!("Token {token}"));
    }

    let response = request.send().map_err(|e| format!("HTTP request failed: {e}"))?;

    if response.status().is_success() {
        Ok(events.len())
    } else {
        let status = response.status();
        let body = response.text().unwrap_or_default();
        Err(format!("Remote rejected data: {status} -- {body}"))
    }
}

/// Read local telemetry events from the JSONL file.
pub fn read_local_events() -> Vec<TelemetryEvent> {
    let path = default_telemetry_path();
    if !path.exists() {
        return Vec::new();
    }
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    content
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_fingerprint_is_stable() {
        let fp1 = system_fingerprint();
        let fp2 = system_fingerprint();
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 16); // 8 bytes = 16 hex chars
    }

    #[test]
    fn telemetry_disabled_by_default() {
        // Remove the env var if set
        std::env::remove_var("AEGIS_TELEMETRY");
        assert!(!is_enabled());
    }

    #[test]
    fn event_serialization() {
        let event = TelemetryEvent {
            schema_version: 1,
            system_id: "abc123".into(),
            agent: "ClaudeCode".into(),
            probe_name: "test-probe".into(),
            category: "PromptInjection".into(),
            severity: "High".into(),
            verdict: "Pass".into(),
            duration_ms: 5000,
            finding_count: 0,
            agent_refused: false,
            timestamp: "2026-03-13T00:00:00Z".into(),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("test-probe"));
        assert!(json.contains("schema_version"));

        // Roundtrip
        let decoded: TelemetryEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.probe_name, "test-probe");
    }

    #[test]
    fn line_protocol_format() {
        let event = TelemetryEvent {
            schema_version: 1,
            system_id: "abc123".into(),
            agent: "ClaudeCode".into(),
            probe_name: "code-comment-injection".into(),
            category: "PromptInjection".into(),
            severity: "High".into(),
            verdict: "Pass".into(),
            duration_ms: 5000,
            finding_count: 0,
            agent_refused: false,
            timestamp: "2026-03-13T00:00:00Z".into(),
        };

        let line = event_to_line_protocol(&event);
        assert!(line.starts_with("aegis_probe,"));
        assert!(line.contains("agent=ClaudeCode"));
        assert!(line.contains("verdict=Pass"));
        assert!(line.contains("duration_ms=5000u"));
        assert!(line.contains("probe_name=\"code-comment-injection\""));
    }

    #[test]
    fn line_protocol_escapes_special_chars() {
        let event = TelemetryEvent {
            schema_version: 1,
            system_id: "abc=123".into(),
            agent: "My Agent".into(),
            probe_name: "test,probe".into(),
            category: "PromptInjection".into(),
            severity: "High".into(),
            verdict: "Pass".into(),
            duration_ms: 100,
            finding_count: 0,
            agent_refused: false,
            timestamp: "2026-03-13T00:00:00Z".into(),
        };

        let line = event_to_line_protocol(&event);
        // Tags should escape spaces, commas, equals
        assert!(line.contains("agent=My\\ Agent"));
        assert!(line.contains("system_id=abc\\=123"));
        // Field strings should escape commas inside quotes
        assert!(line.contains("probe_name=\"test,probe\""));
    }
}
