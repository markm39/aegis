//! Waiver policy loading and gate-time report suppression.
//!
//! Waivers intentionally preserve the raw report while producing an effective
//! report for CI gating and longitudinal analysis. This lets teams document
//! accepted risk without losing the underlying evidence.

use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::scoring::{self, SecurityReport, Verdict};
use crate::testcase::Severity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaiverSet {
    pub schema_version: u32,
    #[serde(default)]
    pub waivers: Vec<WaiverEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaiverEntry {
    pub id: String,
    pub probe: String,
    #[serde(default)]
    pub scope: WaiverScope,
    pub reason: String,
    pub owner: String,
    pub expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity_override: Option<Severity>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WaiverScope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selected_tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selected_profiles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppliedWaiver {
    pub id: String,
    pub probe_name: String,
    pub owner: String,
    pub reason: String,
    pub expires_at: String,
    pub raw_verdict: String,
    pub effective_verdict: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity_override: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpiredWaiver {
    pub id: String,
    pub probe_name: String,
    pub owner: String,
    pub expired_at: String,
}

#[derive(Debug, Clone)]
pub struct WaiverEvaluation {
    pub effective_report: SecurityReport,
    pub applied: Vec<AppliedWaiver>,
    pub expired: Vec<ExpiredWaiver>,
}

pub fn load_waivers(path: &Path) -> Result<WaiverSet, String> {
    let data = std::fs::read_to_string(path)
        .map_err(|err| format!("Error reading {}: {err}", path.display()))?;

    let waivers = match path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase())
        .as_deref()
    {
        Some("json") => serde_json::from_str(&data)
            .map_err(|err| format!("Error parsing {}: {err}", path.display()))?,
        _ => toml::from_str(&data)
            .map_err(|err| format!("Error parsing {}: {err}", path.display()))?,
    };

    validate_waivers(&waivers)?;
    Ok(waivers)
}

pub fn apply_waivers(
    report: &SecurityReport,
    waivers: &WaiverSet,
) -> Result<WaiverEvaluation, String> {
    let mut effective_results = report.results.clone();
    let mut applied = Vec::new();
    let mut expired = Vec::new();

    for (index, result) in report.results.iter().enumerate() {
        if result.verdict == Verdict::Pass {
            continue;
        }

        let mut matches = Vec::new();
        for waiver in &waivers.waivers {
            if !waiver.probe.eq_ignore_ascii_case(&result.probe_name) {
                continue;
            }

            let expires_at = parse_expiry(waiver)?;
            if expires_at < Utc::now() {
                expired.push(ExpiredWaiver {
                    id: waiver.id.clone(),
                    probe_name: result.probe_name.clone(),
                    owner: waiver.owner.clone(),
                    expired_at: waiver.expires_at.clone(),
                });
                continue;
            }

            if waiver_matches(waiver, report, result) {
                matches.push(waiver);
            }
        }

        if matches.len() > 1 {
            let ids = matches
                .iter()
                .map(|waiver| waiver.id.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(format!(
                "Multiple waivers matched probe '{}' for agent '{}': {}. Narrow the scope so only one waiver applies.",
                result.probe_name, report.agent, ids
            ));
        }

        let Some(waiver) = matches.first() else {
            continue;
        };

        let severity_cap = waiver.severity_override.unwrap_or(Severity::Info);
        let effective = &mut effective_results[index];
        effective.verdict = Verdict::Pass;
        effective.severity = effective.severity.min(severity_cap);
        for finding in &mut effective.findings {
            finding.severity = finding.severity.min(severity_cap);
        }

        applied.push(AppliedWaiver {
            id: waiver.id.clone(),
            probe_name: result.probe_name.clone(),
            owner: waiver.owner.clone(),
            reason: waiver.reason.clone(),
            expires_at: waiver.expires_at.clone(),
            raw_verdict: format!("{:?}", result.verdict),
            effective_verdict: "Pass".into(),
            severity_override: waiver
                .severity_override
                .map(|severity| format!("{severity:?}")),
        });
    }

    let mut effective_report = scoring::recompute_report_with_metadata(
        report,
        effective_results,
        report.metadata.selected_tags.clone(),
        report.metadata.selected_profiles.clone(),
    );
    effective_report.metadata.applied_waivers = applied.clone();

    Ok(WaiverEvaluation {
        effective_report,
        applied,
        expired,
    })
}

fn validate_waivers(waivers: &WaiverSet) -> Result<(), String> {
    if waivers.schema_version == 0 {
        return Err("Waiver file schema_version must be greater than zero.".into());
    }

    let mut seen_ids = std::collections::HashSet::new();
    for waiver in &waivers.waivers {
        if waiver.id.trim().is_empty() {
            return Err("Waiver entries require a non-empty id.".into());
        }
        if !seen_ids.insert(waiver.id.to_ascii_lowercase()) {
            return Err(format!("Duplicate waiver id '{}'.", waiver.id));
        }
        if waiver.probe.trim().is_empty() {
            return Err(format!(
                "Waiver '{}' requires a non-empty probe.",
                waiver.id
            ));
        }
        if waiver.owner.trim().is_empty() {
            return Err(format!(
                "Waiver '{}' requires a non-empty owner.",
                waiver.id
            ));
        }
        if waiver.reason.trim().is_empty() {
            return Err(format!(
                "Waiver '{}' requires a non-empty reason.",
                waiver.id
            ));
        }
        parse_expiry(waiver)?;
    }

    Ok(())
}

fn parse_expiry(waiver: &WaiverEntry) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(&waiver.expires_at)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|err| {
            format!(
                "Waiver '{}' has invalid expires_at '{}': {err}",
                waiver.id, waiver.expires_at
            )
        })
}

fn waiver_matches(
    waiver: &WaiverEntry,
    report: &SecurityReport,
    result: &scoring::ProbeResult,
) -> bool {
    if waiver
        .scope
        .agent
        .as_ref()
        .is_some_and(|agent| !report.agent.eq_ignore_ascii_case(agent))
    {
        return false;
    }

    if !waiver.scope.tags.iter().all(|tag| {
        result
            .tags
            .iter()
            .any(|value| value.eq_ignore_ascii_case(tag))
    }) {
        return false;
    }

    if !waiver.scope.selected_tags.iter().all(|tag| {
        report
            .metadata
            .selected_tags
            .iter()
            .any(|value| value.eq_ignore_ascii_case(tag))
    }) {
        return false;
    }

    waiver.scope.selected_profiles.iter().all(|profile| {
        report
            .metadata
            .selected_profiles
            .iter()
            .any(|value| value.eq_ignore_ascii_case(profile))
    })
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use crate::scoring::{Finding, FindingKind, ProbeResult, ReportContext, SecurityReport};
    use crate::testcase::{AttackCategory, Severity};

    use super::*;

    fn sample_report() -> SecurityReport {
        let report = crate::scoring::compute_report_with_context(
            "ClaudeCode",
            vec![ProbeResult {
                probe_name: "sbom-report-injection".into(),
                tags: vec!["sbom".into(), "ci-artifact".into()],
                category: AttackCategory::PromptInjection,
                severity: Severity::Critical,
                verdict: Verdict::Fail,
                findings: vec![Finding {
                    description: "Forbidden file read: ~/.docker/config.json".into(),
                    kind: FindingKind::ForbiddenAction,
                    severity: Severity::Critical,
                    evidence: None,
                }],
                agent: "ClaudeCode".into(),
                duration_ms: 1000,
                timestamp: Utc::now(),
                output_length: 0,
                agent_output: None,
            }],
            &ReportContext {
                probe_pack_hash: "pack-123".into(),
                selected_tags: vec!["ci-artifact".into()],
                selected_profiles: vec!["github-actions".into()],
                executed_tags: vec!["ci-artifact".into(), "sbom".into()],
            },
        );
        report
    }

    #[test]
    fn apply_waiver_suppresses_gate_report() {
        let waivers = WaiverSet {
            schema_version: 1,
            waivers: vec![WaiverEntry {
                id: "waiver-1".into(),
                probe: "sbom-report-injection".into(),
                scope: WaiverScope {
                    agent: Some("ClaudeCode".into()),
                    tags: vec!["sbom".into()],
                    selected_tags: vec!["ci-artifact".into()],
                    selected_profiles: vec!["github-actions".into()],
                },
                reason: "Known issue pending sandbox hardening".into(),
                owner: "security@example.com".into(),
                expires_at: "2099-01-01T00:00:00Z".into(),
                severity_override: Some(Severity::Low),
            }],
        };

        let evaluation = apply_waivers(&sample_report(), &waivers).unwrap();
        assert_eq!(evaluation.applied.len(), 1);
        assert_eq!(evaluation.effective_report.summary.failed, 0);
        assert_eq!(evaluation.effective_report.summary.passed, 1);
        assert_eq!(
            evaluation.effective_report.metadata.applied_waivers[0].id,
            "waiver-1"
        );
        assert_eq!(
            evaluation.effective_report.results[0].findings[0].severity,
            Severity::Low
        );
    }

    #[test]
    fn expired_waiver_is_reported_but_not_applied() {
        let waivers = WaiverSet {
            schema_version: 1,
            waivers: vec![WaiverEntry {
                id: "waiver-expired".into(),
                probe: "sbom-report-injection".into(),
                scope: WaiverScope::default(),
                reason: "Expired".into(),
                owner: "security@example.com".into(),
                expires_at: "2020-01-01T00:00:00Z".into(),
                severity_override: None,
            }],
        };

        let evaluation = apply_waivers(&sample_report(), &waivers).unwrap();
        assert!(evaluation.applied.is_empty());
        assert_eq!(evaluation.expired.len(), 1);
        assert_eq!(evaluation.effective_report.summary.failed, 1);
    }

    #[test]
    fn invalid_waiver_expiry_is_rejected() {
        let waivers = WaiverSet {
            schema_version: 1,
            waivers: vec![WaiverEntry {
                id: "bad-expiry".into(),
                probe: "probe-a".into(),
                scope: WaiverScope::default(),
                reason: "Broken".into(),
                owner: "security@example.com".into(),
                expires_at: "not-a-date".into(),
                severity_override: None,
            }],
        };

        let err = validate_waivers(&waivers).unwrap_err();
        assert!(err.contains("invalid expires_at"));
    }
}
