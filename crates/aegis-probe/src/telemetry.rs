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
fn result_to_event(result: &ProbeResult) -> TelemetryEvent {
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
fn default_telemetry_path() -> PathBuf {
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
}
