//! Derived-only registry bundle export and upload.
//!
//! The registry bundle is designed for hosted aggregation without shipping raw
//! prompts or raw agent output off the machine by default.

use serde::{Deserialize, Serialize};

use crate::fingerprint::{self, BehavioralFingerprint, ModelFingerprint};
use crate::history::{
    self, CategoryTrend, HistoryWindow, NumericTrend, ProbeRegression, UnstableProbe,
};
use crate::scoring::{FindingKind, ReportMetadata, ReportSummary, SecurityReport};

/// A registry-safe bundle derived from a full local report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryBundle {
    pub schema_version: u32,
    pub agent: String,
    pub metadata: ReportMetadata,
    pub score: u32,
    pub summary: ReportSummary,
    pub probes: Vec<RegistryProbeRecord>,
    pub behavioral_fingerprint: BehavioralFingerprint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_fingerprint: Option<ModelFingerprint>,
    pub generated_at: String,
}

/// A registry-safe longitudinal bundle derived from multiple local reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryHistoryBundle {
    pub schema_version: u32,
    pub agent: String,
    pub latest_metadata: ReportMetadata,
    pub latest_summary: ReportSummary,
    pub run_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tag_filter: Vec<String>,
    pub window: HistoryWindow,
    pub score: NumericTrend,
    pub overall_pass_rate: NumericTrend,
    pub category_trends: Vec<CategoryTrend>,
    pub regressions: Vec<ProbeRegression>,
    pub unstable_probes: Vec<UnstableProbe>,
    pub generated_at: String,
}

/// Per-probe registry-safe record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryProbeRecord {
    pub probe_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    pub category: String,
    pub severity: String,
    pub verdict: String,
    pub duration_ms: u64,
    pub output_length: usize,
    pub finding_count: usize,
    pub finding_kinds: Vec<String>,
    pub finding_severities: Vec<String>,
    pub agent_refused: bool,
}

/// Remote registry endpoint configuration.
#[derive(Debug, Clone)]
pub struct RegistryConfig {
    pub url: String,
    pub token: Option<String>,
    pub using_legacy_aliases: bool,
}

/// Build a registry-safe bundle from a local report.
pub fn bundle_from_report(report: &SecurityReport) -> RegistryBundle {
    let has_output = report
        .results
        .iter()
        .any(|result| result.agent_output.is_some());

    RegistryBundle {
        schema_version: 2,
        agent: report.agent.clone(),
        metadata: report.metadata.clone(),
        score: report.score,
        summary: report.summary.clone(),
        probes: report
            .results
            .iter()
            .map(|result| RegistryProbeRecord {
                probe_name: result.probe_name.clone(),
                tags: result.tags.clone(),
                category: format!("{:?}", result.category),
                severity: format!("{:?}", result.severity),
                verdict: format!("{:?}", result.verdict),
                duration_ms: result.duration_ms,
                output_length: result.output_length,
                finding_count: result.findings.len(),
                finding_kinds: result
                    .findings
                    .iter()
                    .map(|finding| match finding.kind {
                        FindingKind::ForbiddenAction => "forbidden_action",
                        FindingKind::CompromiseIndicator => "compromise_indicator",
                        FindingKind::AgentRefused => "agent_refused",
                        FindingKind::AttackExecuted => "attack_executed",
                        FindingKind::Suspicious => "suspicious",
                    })
                    .map(str::to_string)
                    .collect(),
                finding_severities: result
                    .findings
                    .iter()
                    .map(|finding| format!("{:?}", finding.severity))
                    .collect(),
                agent_refused: result
                    .findings
                    .iter()
                    .any(|finding| matches!(finding.kind, FindingKind::AgentRefused)),
            })
            .collect(),
        behavioral_fingerprint: fingerprint::extract_fingerprint(report),
        model_fingerprint: has_output.then(|| fingerprint::extract_model_fingerprint(report)),
        generated_at: chrono::Utc::now().to_rfc3339(),
    }
}

/// Build a registry-safe longitudinal bundle from compatible local reports.
pub fn history_bundle_from_reports(
    reports: &[SecurityReport],
    tag_filter: &[String],
) -> RegistryHistoryBundle {
    let analysis = history::analyze_history(reports, tag_filter);
    let latest = reports
        .last()
        .expect("history_bundle_from_reports requires at least one report");

    RegistryHistoryBundle {
        schema_version: 1,
        agent: analysis.agent,
        latest_metadata: latest.metadata.clone(),
        latest_summary: latest.summary.clone(),
        run_count: analysis.run_count,
        tag_filter: analysis.tag_filter,
        window: analysis.window,
        score: analysis.score,
        overall_pass_rate: analysis.overall_pass_rate,
        category_trends: analysis.category_trends,
        regressions: analysis.regressions,
        unstable_probes: analysis.unstable_probes,
        generated_at: analysis.generated_at,
    }
}

/// Resolve registry configuration from environment.
///
/// `AEGIS_REGISTRY_URL` and `AEGIS_REGISTRY_TOKEN` are preferred. The older
/// telemetry names are accepted as deprecated aliases for one release cycle.
pub fn registry_config() -> Option<RegistryConfig> {
    let url = std::env::var("AEGIS_REGISTRY_URL")
        .ok()
        .or_else(|| std::env::var("AEGIS_TELEMETRY_URL").ok())?;
    let token = std::env::var("AEGIS_REGISTRY_TOKEN")
        .ok()
        .or_else(|| std::env::var("AEGIS_TELEMETRY_TOKEN").ok());
    let using_legacy_aliases = std::env::var("AEGIS_REGISTRY_URL").is_err()
        && std::env::var("AEGIS_TELEMETRY_URL").is_ok();

    Some(RegistryConfig {
        url,
        token,
        using_legacy_aliases,
    })
}

/// Upload a derived-only bundle to a configured registry endpoint.
pub fn upload_bundle(bundle: &RegistryBundle, config: &RegistryConfig) -> Result<(), String> {
    upload_json(bundle, config)
}

/// Upload a derived-only longitudinal bundle to a configured registry endpoint.
pub fn upload_history_bundle(
    bundle: &RegistryHistoryBundle,
    config: &RegistryConfig,
) -> Result<(), String> {
    upload_json(bundle, config)
}

fn upload_json<T: Serialize>(payload: &T, config: &RegistryConfig) -> Result<(), String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|err| format!("HTTP client error: {err}"))?;

    let mut request = client
        .post(&config.url)
        .header("Content-Type", "application/json")
        .json(payload);

    if let Some(token) = &config.token {
        request = request.header("Authorization", format!("Bearer {token}"));
    }

    let response = request
        .send()
        .map_err(|err| format!("HTTP request failed: {err}"))?;

    if response.status().is_success() {
        Ok(())
    } else {
        let status = response.status();
        let body = response.text().unwrap_or_default();
        Err(format!("Registry rejected bundle: {status} -- {body}"))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, OnceLock};

    use chrono::Utc;

    use crate::scoring::{
        Finding, ProbeResult, ReportMetadata, ReportSummary, SecurityReport, Verdict,
    };
    use crate::testcase::{AttackCategory, Severity};

    use super::*;

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn sample_report() -> SecurityReport {
        SecurityReport {
            score: 75,
            agent: "TestAgent".into(),
            metadata: ReportMetadata {
                schema_version: 3,
                runner_version: "0.1.0".into(),
                probe_pack_hash: "abc123".into(),
                selected_tags: vec!["ci-artifact".into()],
                executed_tags: vec!["ci-artifact".into(), "credential-theft".into()],
                ..ReportMetadata::default()
            },
            results: vec![ProbeResult {
                probe_name: "probe-1".into(),
                tags: vec!["ci-artifact".into(), "credential-theft".into()],
                category: AttackCategory::PromptInjection,
                severity: Severity::High,
                verdict: Verdict::Pass,
                findings: vec![Finding {
                    description: "Agent explicitly refused the adversarial request".into(),
                    kind: FindingKind::AgentRefused,
                    severity: Severity::Info,
                    evidence: Some("local-only".into()),
                }],
                agent: "TestAgent".into(),
                duration_ms: 1200,
                timestamp: Utc::now(),
                output_length: 42,
                agent_output: Some("I cannot do that.".into()),
            }],
            summary: ReportSummary {
                total_probes: 1,
                passed: 1,
                partial: 0,
                failed: 0,
                errors: 0,
                critical_findings: 0,
                high_findings: 0,
            },
            timestamp: Utc::now(),
        }
    }

    fn sample_history_reports() -> Vec<SecurityReport> {
        let first = sample_report();
        let mut second = sample_report();
        second.score = 0;
        second.summary = ReportSummary {
            total_probes: 1,
            passed: 0,
            partial: 0,
            failed: 1,
            errors: 0,
            critical_findings: 0,
            high_findings: 1,
        };
        second.results[0].verdict = Verdict::Fail;
        second.timestamp = first.timestamp + chrono::TimeDelta::seconds(30);
        vec![first, second]
    }

    #[test]
    fn bundle_excludes_raw_agent_output() {
        let bundle = bundle_from_report(&sample_report());
        let serialized = serde_json::to_string(&bundle).unwrap();
        assert!(!serialized.contains("I cannot do that."));
        assert!(!serialized.contains("local-only"));
        assert!(serialized.contains("behavioral_fingerprint"));
        assert!(serialized.contains("\"tags\":[\"ci-artifact\",\"credential-theft\"]"));
        assert!(serialized.contains("\"selected_tags\":[\"ci-artifact\"]"));
    }

    #[test]
    fn history_bundle_excludes_raw_agent_output() {
        let bundle =
            history_bundle_from_reports(&sample_history_reports(), &["ci-artifact".into()]);
        let serialized = serde_json::to_string(&bundle).unwrap();
        assert!(!serialized.contains("I cannot do that."));
        assert!(!serialized.contains("local-only"));
        assert!(serialized.contains("\"tag_filter\":[\"ci-artifact\"]"));
        assert!(serialized.contains("\"regressions\":["));
        assert!(serialized.contains("\"probe_name\":\"probe-1\""));
    }

    #[test]
    fn registry_config_accepts_legacy_aliases() {
        let _guard = env_lock().lock().unwrap();
        std::env::remove_var("AEGIS_REGISTRY_URL");
        std::env::remove_var("AEGIS_REGISTRY_TOKEN");
        std::env::set_var(
            "AEGIS_TELEMETRY_URL",
            "https://registry.example.test/upload",
        );

        let config = registry_config().expect("config should resolve");
        assert!(config.using_legacy_aliases);
        assert_eq!(config.url, "https://registry.example.test/upload");

        std::env::remove_var("AEGIS_TELEMETRY_URL");
    }
}
