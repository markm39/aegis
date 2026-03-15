//! Waiver policy loading and gate-time report suppression.
//!
//! Waivers intentionally preserve the raw report while producing an effective
//! report for CI gating and longitudinal analysis. This lets teams document
//! accepted risk without losing the underlying evidence.

use std::collections::HashSet;
use std::path::Path;

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::scoring::{self, SecurityReport, Verdict};
use crate::testcase::Severity;

type HmacSha256 = Hmac<Sha256>;

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<String>,
    #[serde(default)]
    pub signed: bool,
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

#[derive(Debug, Clone)]
pub struct WaiverValidationPolicy {
    pub require_signatures: bool,
    pub key_env: String,
    pub signing_key: Option<String>,
}

impl Default for WaiverValidationPolicy {
    fn default() -> Self {
        Self {
            require_signatures: false,
            key_env: "AEGIS_WAIVER_SIGNING_KEY".into(),
            signing_key: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WaiverLifecycleStatus {
    Active,
    Expired,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    Valid,
    Missing,
    Invalid,
    Unverified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaiverAuditEntry {
    pub id: String,
    pub probe: String,
    pub owner: String,
    pub expires_at: String,
    pub days_until_expiry: i64,
    pub lifecycle_status: WaiverLifecycleStatus,
    pub signature_status: SignatureStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaiverAuditSummary {
    pub total: usize,
    pub active: usize,
    pub expired: usize,
    pub expiring_within_window: usize,
    pub valid_signatures: usize,
    pub missing_signatures: usize,
    pub invalid_signatures: usize,
    pub unverified_signatures: usize,
    pub policy_compliant: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaiverAuditReport {
    pub schema_version: u32,
    pub generated_at: String,
    pub expiring_within_days: i64,
    pub require_signatures: bool,
    pub verification_key_loaded: bool,
    pub summary: WaiverAuditSummary,
    pub waivers: Vec<WaiverAuditEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WaiverSummary {
    pub applied_count: usize,
    pub signed_count: usize,
    pub unsigned_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owners: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tickets: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expiring_within_30_days: Vec<String>,
}

pub fn load_waivers(path: &Path) -> Result<WaiverSet, String> {
    load_waivers_with_policy(path, &WaiverValidationPolicy::default())
}

pub fn load_waivers_with_policy(
    path: &Path,
    policy: &WaiverValidationPolicy,
) -> Result<WaiverSet, String> {
    let waivers = read_waivers(path)?;
    validate_waivers(&waivers, policy)?;
    Ok(waivers)
}

pub fn audit_waivers_from_path(
    path: &Path,
    policy: &WaiverValidationPolicy,
    expiring_within_days: i64,
) -> Result<WaiverAuditReport, String> {
    if expiring_within_days < 0 {
        return Err("Waiver audit window must be zero or greater.".into());
    }

    let waivers = read_waivers(path)?;
    basic_validate_waivers(&waivers)?;
    let signing_key = resolve_signing_key(policy, false)?;
    let now = Utc::now();

    let mut entries = Vec::with_capacity(waivers.waivers.len());
    let mut active = 0;
    let mut expired = 0;
    let mut expiring_within_window = 0;
    let mut valid_signatures = 0;
    let mut missing_signatures = 0;
    let mut invalid_signatures = 0;
    let mut unverified_signatures = 0;
    let mut policy_compliant = true;

    for waiver in &waivers.waivers {
        let expires_at = parse_expiry(waiver)?;
        let days_until_expiry = expires_at.signed_duration_since(now).num_days();
        let lifecycle_status = if expires_at < now {
            expired += 1;
            WaiverLifecycleStatus::Expired
        } else {
            active += 1;
            if days_until_expiry <= expiring_within_days {
                expiring_within_window += 1;
            }
            WaiverLifecycleStatus::Active
        };

        let signature_status = signature_status(waiver, signing_key.as_deref())?;
        match signature_status {
            SignatureStatus::Valid => valid_signatures += 1,
            SignatureStatus::Missing => missing_signatures += 1,
            SignatureStatus::Invalid => invalid_signatures += 1,
            SignatureStatus::Unverified => unverified_signatures += 1,
        }

        if policy.require_signatures && signature_status != SignatureStatus::Valid {
            policy_compliant = false;
        }

        entries.push(WaiverAuditEntry {
            id: waiver.id.clone(),
            probe: waiver.probe.clone(),
            owner: waiver.owner.clone(),
            expires_at: waiver.expires_at.clone(),
            days_until_expiry,
            lifecycle_status,
            signature_status,
            ticket: waiver.ticket.clone(),
            approved_by: waiver.approved_by.clone(),
            approved_at: waiver.approved_at.clone(),
        });
    }

    entries.sort_by(|a, b| {
        a.expires_at
            .cmp(&b.expires_at)
            .then_with(|| a.id.to_ascii_lowercase().cmp(&b.id.to_ascii_lowercase()))
    });

    Ok(WaiverAuditReport {
        schema_version: 1,
        generated_at: now.to_rfc3339(),
        expiring_within_days,
        require_signatures: policy.require_signatures,
        verification_key_loaded: signing_key.is_some(),
        summary: WaiverAuditSummary {
            total: entries.len(),
            active,
            expired,
            expiring_within_window,
            valid_signatures,
            missing_signatures,
            invalid_signatures,
            unverified_signatures,
            policy_compliant,
        },
        waivers: entries,
    })
}

pub fn sign_waivers(
    waivers: &WaiverSet,
    policy: &WaiverValidationPolicy,
) -> Result<WaiverSet, String> {
    basic_validate_waivers(waivers)?;
    let signing_key = resolve_signing_key(policy, true)?.ok_or_else(|| {
        format!(
            "Waiver signing key env var '{}' is not set.",
            policy.key_env
        )
    })?;

    let mut signed = waivers.clone();
    signed.schema_version = signed.schema_version.max(2);

    for waiver in &mut signed.waivers {
        validate_signable_waiver(waiver)?;
        waiver.signature = Some(compute_signature(waiver, &signing_key)?);
    }

    validate_waivers(
        &signed,
        &WaiverValidationPolicy {
            require_signatures: true,
            key_env: policy.key_env.clone(),
            signing_key: Some(signing_key),
        },
    )?;

    Ok(signed)
}

pub fn summarize_applied_waivers(applied: &[AppliedWaiver]) -> WaiverSummary {
    let mut owners = applied
        .iter()
        .map(|waiver| waiver.owner.clone())
        .collect::<Vec<_>>();
    owners.sort();
    owners.dedup();

    let mut tickets = applied
        .iter()
        .filter_map(|waiver| waiver.ticket.clone())
        .collect::<Vec<_>>();
    tickets.sort();
    tickets.dedup();

    let now = Utc::now();
    let mut expiring_within_30_days = applied
        .iter()
        .filter_map(|waiver| {
            DateTime::parse_from_rfc3339(&waiver.expires_at)
                .ok()
                .map(|value| value.with_timezone(&Utc))
                .filter(|expires_at| {
                    *expires_at >= now && expires_at.signed_duration_since(now).num_days() <= 30
                })
                .map(|_| waiver.id.clone())
        })
        .collect::<Vec<_>>();
    expiring_within_30_days.sort();
    expiring_within_30_days.dedup();

    let signed_count = applied.iter().filter(|waiver| waiver.signed).count();

    WaiverSummary {
        applied_count: applied.len(),
        signed_count,
        unsigned_count: applied.len().saturating_sub(signed_count),
        owners,
        tickets,
        expiring_within_30_days,
    }
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
            ticket: waiver.ticket.clone(),
            approved_by: waiver.approved_by.clone(),
            approved_at: waiver.approved_at.clone(),
            signed: waiver.signature.is_some(),
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

fn read_waivers(path: &Path) -> Result<WaiverSet, String> {
    let data = std::fs::read_to_string(path)
        .map_err(|err| format!("Error reading {}: {err}", path.display()))?;

    match path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase())
        .as_deref()
    {
        Some("json") => serde_json::from_str(&data)
            .map_err(|err| format!("Error parsing {}: {err}", path.display())),
        _ => {
            toml::from_str(&data).map_err(|err| format!("Error parsing {}: {err}", path.display()))
        }
    }
}

fn validate_waivers(waivers: &WaiverSet, policy: &WaiverValidationPolicy) -> Result<(), String> {
    basic_validate_waivers(waivers)?;
    let signing_key = resolve_signing_key(policy, policy.require_signatures)?;

    for waiver in &waivers.waivers {
        let status = signature_status(waiver, signing_key.as_deref())?;
        if policy.require_signatures && status != SignatureStatus::Valid {
            return Err(match status {
                SignatureStatus::Missing => format!(
                    "Waiver '{}' is missing a signature. Re-sign the waiver file with `aegis-probe waivers sign`.",
                    waiver.id
                ),
                SignatureStatus::Invalid => format!(
                    "Waiver '{}' has an invalid signature.",
                    waiver.id
                ),
                SignatureStatus::Unverified => format!(
                    "Waiver '{}' could not be verified because signing key env var '{}' is not set.",
                    waiver.id, policy.key_env
                ),
                SignatureStatus::Valid => unreachable!("validated above"),
            });
        }
        if status == SignatureStatus::Invalid {
            return Err(format!("Waiver '{}' has an invalid signature.", waiver.id));
        }
    }

    Ok(())
}

fn basic_validate_waivers(waivers: &WaiverSet) -> Result<(), String> {
    if waivers.schema_version == 0 {
        return Err("Waiver file schema_version must be greater than zero.".into());
    }

    let mut seen_ids = HashSet::new();
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
        validate_optional_field(&waiver.ticket, "ticket", &waiver.id)?;
        parse_expiry(waiver)?;
        validate_approval_fields(waiver)?;
    }

    Ok(())
}

fn validate_optional_field(value: &Option<String>, name: &str, id: &str) -> Result<(), String> {
    if value.as_ref().is_some_and(|value| value.trim().is_empty()) {
        return Err(format!("Waiver '{}' requires a non-empty {}.", id, name));
    }
    Ok(())
}

fn validate_signable_waiver(waiver: &WaiverEntry) -> Result<(), String> {
    if waiver
        .approved_by
        .as_ref()
        .is_none_or(|value| value.trim().is_empty())
    {
        return Err(format!(
            "Waiver '{}' requires approved_by before it can be signed.",
            waiver.id
        ));
    }
    if waiver
        .approved_at
        .as_ref()
        .is_none_or(|value| value.trim().is_empty())
    {
        return Err(format!(
            "Waiver '{}' requires approved_at before it can be signed.",
            waiver.id
        ));
    }
    parse_approved_at(waiver)?;
    Ok(())
}

fn validate_approval_fields(waiver: &WaiverEntry) -> Result<(), String> {
    validate_optional_field(&waiver.approved_by, "approved_by", &waiver.id)?;
    validate_optional_field(&waiver.approved_at, "approved_at", &waiver.id)?;
    validate_optional_field(&waiver.signature, "signature", &waiver.id)?;

    if waiver.signature.is_some() {
        if waiver.approved_by.is_none() {
            return Err(format!(
                "Waiver '{}' requires approved_by when a signature is present.",
                waiver.id
            ));
        }
        if waiver.approved_at.is_none() {
            return Err(format!(
                "Waiver '{}' requires approved_at when a signature is present.",
                waiver.id
            ));
        }
    }

    if waiver.approved_at.is_some() {
        parse_approved_at(waiver)?;
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

fn parse_approved_at(waiver: &WaiverEntry) -> Result<DateTime<Utc>, String> {
    let Some(approved_at) = waiver.approved_at.as_deref() else {
        return Err(format!(
            "Waiver '{}' requires approved_at when a signature is present.",
            waiver.id
        ));
    };

    DateTime::parse_from_rfc3339(approved_at)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|err| {
            format!(
                "Waiver '{}' has invalid approved_at '{}': {err}",
                waiver.id, approved_at
            )
        })
}

fn resolve_signing_key(
    policy: &WaiverValidationPolicy,
    required: bool,
) -> Result<Option<String>, String> {
    if let Some(signing_key) = policy.signing_key.as_ref() {
        if signing_key.trim().is_empty() {
            return Err("Waiver signing key must not be empty.".into());
        }
        return Ok(Some(signing_key.clone()));
    }

    match std::env::var(&policy.key_env) {
        Ok(value) if value.trim().is_empty() => Err(format!(
            "Waiver signing key env var '{}' is empty.",
            policy.key_env
        )),
        Ok(value) => Ok(Some(value)),
        Err(_) if required => Err(format!(
            "Waiver signing key env var '{}' is not set.",
            policy.key_env
        )),
        Err(_) => Ok(None),
    }
}

fn signature_status(
    waiver: &WaiverEntry,
    signing_key: Option<&str>,
) -> Result<SignatureStatus, String> {
    let Some(signature) = waiver.signature.as_deref() else {
        return Ok(SignatureStatus::Missing);
    };

    if signature.trim().is_empty() {
        return Err(format!(
            "Waiver '{}' requires a non-empty signature.",
            waiver.id
        ));
    }

    let Some(signing_key) = signing_key else {
        return Ok(SignatureStatus::Unverified);
    };

    if verify_signature(waiver, signing_key, signature)? {
        Ok(SignatureStatus::Valid)
    } else {
        Ok(SignatureStatus::Invalid)
    }
}

fn verify_signature(
    waiver: &WaiverEntry,
    signing_key: &str,
    signature: &str,
) -> Result<bool, String> {
    let expected = compute_signature(waiver, signing_key)?;
    Ok(expected.eq_ignore_ascii_case(signature.trim()))
}

fn compute_signature(waiver: &WaiverEntry, signing_key: &str) -> Result<String, String> {
    let payload = canonical_waiver_payload(waiver)?;
    let mut mac = HmacSha256::new_from_slice(signing_key.as_bytes())
        .map_err(|err| format!("Error constructing waiver signer: {err}"))?;
    mac.update(&payload);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn canonical_waiver_payload(waiver: &WaiverEntry) -> Result<Vec<u8>, String> {
    #[derive(Serialize)]
    struct CanonicalWaiver<'a> {
        id: &'a str,
        probe: &'a str,
        scope: &'a WaiverScope,
        reason: &'a str,
        owner: &'a str,
        expires_at: &'a str,
        severity_override: Option<Severity>,
        ticket: Option<&'a str>,
        approved_by: Option<&'a str>,
        approved_at: Option<&'a str>,
    }

    serde_json::to_vec(&CanonicalWaiver {
        id: &waiver.id,
        probe: &waiver.probe,
        scope: &waiver.scope,
        reason: &waiver.reason,
        owner: &waiver.owner,
        expires_at: &waiver.expires_at,
        severity_override: waiver.severity_override,
        ticket: waiver.ticket.as_deref(),
        approved_by: waiver.approved_by.as_deref(),
        approved_at: waiver.approved_at.as_deref(),
    })
    .map_err(|err| {
        format!(
            "Error serializing waiver '{}' for signing: {err}",
            waiver.id
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
        crate::scoring::compute_report_with_context(
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
        )
    }

    fn sample_waivers() -> WaiverSet {
        WaiverSet {
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
                ticket: Some("SEC-123".into()),
                approved_by: Some("approver@example.com".into()),
                approved_at: Some("2026-03-14T00:00:00Z".into()),
                signature: None,
            }],
        }
    }

    #[test]
    fn apply_waiver_suppresses_gate_report() {
        let evaluation = apply_waivers(&sample_report(), &sample_waivers()).unwrap();
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
        assert_eq!(
            evaluation.effective_report.metadata.applied_waivers[0]
                .ticket
                .as_deref(),
            Some("SEC-123")
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
                ticket: None,
                approved_by: None,
                approved_at: None,
                signature: None,
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
                ticket: None,
                approved_by: None,
                approved_at: None,
                signature: None,
            }],
        };

        let err = basic_validate_waivers(&waivers).unwrap_err();
        assert!(err.contains("invalid expires_at"));
    }

    #[test]
    fn signing_and_loading_with_required_signatures_succeeds() {
        let policy = WaiverValidationPolicy {
            require_signatures: true,
            key_env: "IGNORED".into(),
            signing_key: Some("secret-signing-key".into()),
        };

        let signed = sign_waivers(&sample_waivers(), &policy).unwrap();
        assert_eq!(signed.schema_version, 2);
        assert!(signed.waivers[0].signature.is_some());
        load_waivers_with_policy(
            Path::new("unused"),
            &WaiverValidationPolicy {
                require_signatures: false,
                key_env: "IGNORED".into(),
                signing_key: Some("secret-signing-key".into()),
            },
        )
        .err();

        validate_waivers(&signed, &policy).unwrap();
    }

    #[test]
    fn audit_reports_invalid_signature() {
        let policy = WaiverValidationPolicy {
            require_signatures: false,
            key_env: "IGNORED".into(),
            signing_key: Some("secret-signing-key".into()),
        };
        let mut signed = sign_waivers(&sample_waivers(), &policy).unwrap();
        signed.waivers[0].reason = "tampered".into();

        let report = {
            let now = Utc::now();
            let entries = signed
                .waivers
                .iter()
                .map(|waiver| WaiverAuditEntry {
                    id: waiver.id.clone(),
                    probe: waiver.probe.clone(),
                    owner: waiver.owner.clone(),
                    expires_at: waiver.expires_at.clone(),
                    days_until_expiry: parse_expiry(waiver)
                        .unwrap()
                        .signed_duration_since(now)
                        .num_days(),
                    lifecycle_status: WaiverLifecycleStatus::Active,
                    signature_status: signature_status(waiver, policy.signing_key.as_deref())
                        .unwrap(),
                    ticket: waiver.ticket.clone(),
                    approved_by: waiver.approved_by.clone(),
                    approved_at: waiver.approved_at.clone(),
                })
                .collect::<Vec<_>>();
            entries
        };

        assert_eq!(report[0].signature_status, SignatureStatus::Invalid);
    }

    #[test]
    fn summarize_applied_waivers_counts_signed_entries() {
        let summary = summarize_applied_waivers(&[
            AppliedWaiver {
                id: "signed".into(),
                probe_name: "probe-a".into(),
                owner: "owner-a".into(),
                reason: "reason".into(),
                expires_at: "2099-01-01T00:00:00Z".into(),
                raw_verdict: "Fail".into(),
                effective_verdict: "Pass".into(),
                severity_override: None,
                ticket: Some("SEC-1".into()),
                approved_by: Some("approver".into()),
                approved_at: Some("2026-03-14T00:00:00Z".into()),
                signed: true,
            },
            AppliedWaiver {
                id: "unsigned".into(),
                probe_name: "probe-b".into(),
                owner: "owner-b".into(),
                reason: "reason".into(),
                expires_at: "2099-01-15T00:00:00Z".into(),
                raw_verdict: "Fail".into(),
                effective_verdict: "Pass".into(),
                severity_override: None,
                ticket: None,
                approved_by: None,
                approved_at: None,
                signed: false,
            },
        ]);

        assert_eq!(summary.applied_count, 2);
        assert_eq!(summary.signed_count, 1);
        assert_eq!(summary.unsigned_count, 1);
        assert_eq!(summary.tickets, vec!["SEC-1"]);
    }
}
