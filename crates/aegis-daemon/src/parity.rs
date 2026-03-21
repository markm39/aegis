//! Parity matrix reporting: parse features.yaml / security_controls.yaml
//! and produce status, diff, and verify reports.

use std::collections::HashSet;
use aegis_control::daemon::{
    ParityDiffReport, ParityFeatureStatus, ParityStatusReport, ParityVerifyReport,
    ParityViolation,
};

#[derive(Debug, Clone, Default)]
pub(crate) struct ParityFeatureRow {
    pub feature_id: String,
    pub status: String,
    pub risk_level: String,
    pub owner: String,
    pub required_controls: Vec<String>,
    pub acceptance_tests: Vec<String>,
    pub evidence_paths: Vec<String>,
}

pub(crate) fn parity_dir() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("AEGIS_PARITY_DIR") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return std::path::PathBuf::from(trimmed);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        return std::path::PathBuf::from(home).join("aegis-parity");
    }
    std::path::PathBuf::from("aegis-parity")
}

pub(crate) fn strip_yaml_scalar(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FeatureListField {
    RequiredControls,
    AcceptanceTests,
    EvidencePaths,
}

pub(crate) fn parse_features_yaml(raw: &str) -> (String, Vec<ParityFeatureRow>) {
    let mut updated_at_utc = String::new();
    let mut rows: Vec<ParityFeatureRow> = Vec::new();
    let mut current: Option<ParityFeatureRow> = None;
    let mut active_list_field: Option<FeatureListField> = None;

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some((k, v)) = trimmed.split_once(':') {
            if k.trim() == "updated_at_utc" {
                updated_at_utc = strip_yaml_scalar(v);
            }
        }

        if let Some(value) = trimmed.strip_prefix("- feature_id:") {
            if let Some(prev) = current.take() {
                if !prev.feature_id.is_empty() {
                    rows.push(prev);
                }
            }
            current = Some(ParityFeatureRow {
                feature_id: strip_yaml_scalar(value),
                ..ParityFeatureRow::default()
            });
            active_list_field = None;
            continue;
        }

        let Some(row) = current.as_mut() else {
            continue;
        };

        if let Some(value) = trimmed.strip_prefix("aegis_status:") {
            row.status = strip_yaml_scalar(value);
            active_list_field = None;
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("risk_level:") {
            row.risk_level = strip_yaml_scalar(value);
            active_list_field = None;
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("owner:") {
            row.owner = strip_yaml_scalar(value);
            active_list_field = None;
            continue;
        }
        if trimmed.starts_with("required_controls:") {
            active_list_field = Some(FeatureListField::RequiredControls);
            continue;
        }
        if trimmed.starts_with("acceptance_tests:") {
            active_list_field = Some(FeatureListField::AcceptanceTests);
            continue;
        }
        if trimmed.starts_with("evidence_paths:") {
            active_list_field = Some(FeatureListField::EvidencePaths);
            continue;
        }
        if let Some(field) = active_list_field {
            if let Some(value) = trimmed.strip_prefix("- ") {
                let item = strip_yaml_scalar(value);
                if !item.is_empty() {
                    match field {
                        FeatureListField::RequiredControls => row.required_controls.push(item),
                        FeatureListField::AcceptanceTests => row.acceptance_tests.push(item),
                        FeatureListField::EvidencePaths => row.evidence_paths.push(item),
                    }
                }
                continue;
            }
            if trimmed.contains(':') {
                active_list_field = None;
            }
        }
    }

    if let Some(prev) = current.take() {
        if !prev.feature_id.is_empty() {
            rows.push(prev);
        }
    }

    (updated_at_utc, rows)
}

pub(crate) fn parse_security_controls_yaml(raw: &str) -> HashSet<String> {
    let mut controls = HashSet::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("- control_id:") {
            let control_id = strip_yaml_scalar(value);
            if !control_id.is_empty() {
                controls.insert(control_id);
            }
        }
    }
    controls
}

fn parity_status_is_valid(status: &str) -> bool {
    matches!(status, "complete" | "partial" | "missing" | "blocked")
}

fn parity_risk_level_is_valid(risk_level: &str) -> bool {
    matches!(risk_level, "low" | "medium" | "high" | "critical")
}

pub(crate) fn parity_status_report_from_dir(
    dir: &std::path::Path,
) -> Result<ParityStatusReport, String> {
    let features_path = dir.join("matrix").join("features.yaml");
    let controls_path = dir.join("matrix").join("security_controls.yaml");

    let features_raw = std::fs::read_to_string(&features_path)
        .map_err(|e| format!("failed to read {}: {e}", features_path.display()))?;
    let controls_raw = std::fs::read_to_string(&controls_path)
        .map_err(|e| format!("failed to read {}: {e}", controls_path.display()))?;

    let (updated_at_utc, rows) = parse_features_yaml(&features_raw);
    let known_controls = parse_security_controls_yaml(&controls_raw);

    let mut complete_features = 0usize;
    let mut partial_features = 0usize;
    let mut high_risk_blockers = 0usize;
    let mut features: Vec<ParityFeatureStatus> = Vec::with_capacity(rows.len());

    for row in rows {
        let status = if row.status.trim().is_empty() {
            "unknown".to_string()
        } else {
            row.status.clone()
        };
        if status == "complete" {
            complete_features += 1;
        } else if status == "partial" {
            partial_features += 1;
        }
        let missing_controls: Vec<String> = row
            .required_controls
            .iter()
            .filter(|c| !known_controls.contains(*c))
            .cloned()
            .collect();

        let is_high_risk = row.risk_level.eq_ignore_ascii_case("high")
            || row.risk_level.eq_ignore_ascii_case("critical");
        if is_high_risk && (status != "complete" || !missing_controls.is_empty()) {
            high_risk_blockers += 1;
        }

        features.push(ParityFeatureStatus {
            feature_id: row.feature_id,
            status,
            risk_level: row.risk_level,
            owner: row.owner,
            required_controls: row.required_controls,
            missing_controls,
        });
    }

    Ok(ParityStatusReport {
        source_dir: dir.display().to_string(),
        updated_at_utc,
        total_features: features.len(),
        complete_features,
        partial_features,
        high_risk_blockers,
        features,
    })
}

pub(crate) fn parity_status_report() -> Result<ParityStatusReport, String> {
    let dir = parity_dir();
    parity_status_report_from_dir(&dir)
}

pub(crate) fn parity_diff_report_from_dir(
    dir: &std::path::Path,
) -> Result<ParityDiffReport, String> {
    let reports_dir = dir.join("reports");
    let mut latest_path: Option<std::path::PathBuf> = None;
    let mut latest_mtime: Option<std::time::SystemTime> = None;

    let entries = std::fs::read_dir(&reports_dir)
        .map_err(|e| format!("failed to read {}: {e}", reports_dir.display()))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let mtime = match entry.metadata().and_then(|m| m.modified()) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if latest_mtime.is_none_or(|current| mtime > current) {
            latest_mtime = Some(mtime);
            latest_path = Some(path);
        }
    }

    let report_path = latest_path
        .ok_or_else(|| format!("no parity reports found in {}", reports_dir.display()))?;
    let raw = std::fs::read_to_string(&report_path)
        .map_err(|e| format!("failed to read {}: {e}", report_path.display()))?;

    let mut upstream_sha = String::new();
    let mut changed_files = 0usize;
    let mut in_changed_files = false;
    for line in raw.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("- new_processed_sha:") {
            upstream_sha = strip_yaml_scalar(value);
        }
        if trimmed == "## Changed Files" {
            in_changed_files = true;
            continue;
        }
        if in_changed_files && trimmed.starts_with("## ") {
            in_changed_files = false;
        }
        if in_changed_files && trimmed.starts_with("- ") {
            changed_files += 1;
        }
    }

    let status = parity_status_report_from_dir(dir)?;
    let impacted_feature_ids = status
        .features
        .into_iter()
        .filter(|f| {
            (f.risk_level.eq_ignore_ascii_case("high")
                || f.risk_level.eq_ignore_ascii_case("critical"))
                && (f.status != "complete")
        })
        .map(|f| f.feature_id)
        .collect::<Vec<_>>();

    Ok(ParityDiffReport {
        report_file: report_path.to_string_lossy().into_owned(),
        upstream_sha,
        changed_files,
        impacted_feature_ids,
    })
}

pub(crate) fn parity_diff_report() -> Result<ParityDiffReport, String> {
    let dir = parity_dir();
    parity_diff_report_from_dir(&dir)
}

pub(crate) fn parity_verify_report_from_dir(
    dir: &std::path::Path,
) -> Result<ParityVerifyReport, String> {
    let features_path = dir.join("matrix").join("features.yaml");
    let controls_path = dir.join("matrix").join("security_controls.yaml");

    let features_raw = std::fs::read_to_string(&features_path)
        .map_err(|e| format!("failed to read {}: {e}", features_path.display()))?;
    let controls_raw = std::fs::read_to_string(&controls_path)
        .map_err(|e| format!("failed to read {}: {e}", controls_path.display()))?;

    let (_, rows) = parse_features_yaml(&features_raw);
    let known_controls = parse_security_controls_yaml(&controls_raw);

    let mut violations = Vec::new();
    let mut violations_struct: Vec<ParityViolation> = Vec::new();
    let mut push_violation = |rule_id: &str, feature_id: &str, message: String| {
        violations.push(format!("{rule_id}|{feature_id}|{message}"));
        violations_struct.push(ParityViolation {
            rule_id: rule_id.to_string(),
            feature_id: feature_id.to_string(),
            message,
        });
    };

    for row in &rows {
        let status = row.status.trim().to_ascii_lowercase();
        let risk_level = row.risk_level.trim().to_ascii_lowercase();

        if !parity_status_is_valid(&status) {
            push_violation(
                "R_STATUS_ENUM",
                &row.feature_id,
                format!("unsupported status '{}'", row.status),
            );
        }
        if !parity_risk_level_is_valid(&risk_level) {
            push_violation(
                "R_RISK_ENUM",
                &row.feature_id,
                format!("unsupported risk level '{}'", row.risk_level),
            );
        }

        let is_complete = status == "complete";
        let is_high_risk = matches!(risk_level.as_str(), "high" | "critical");

        if is_high_risk && !is_complete {
            push_violation(
                "R_HIGH_RISK_COMPLETE",
                &row.feature_id,
                format!(
                    "high/critical feature must be complete (status={})",
                    row.status
                ),
            );
        }

        let missing_controls: Vec<&str> = row
            .required_controls
            .iter()
            .map(String::as_str)
            .filter(|control| !known_controls.contains(*control))
            .collect();

        if is_complete && !missing_controls.is_empty() {
            push_violation(
                "R_COMPLETE_CONTROLS",
                &row.feature_id,
                format!("missing controls: {}", missing_controls.join(", ")),
            );
        }
        if is_complete && row.acceptance_tests.is_empty() {
            push_violation(
                "R_COMPLETE_TESTS",
                &row.feature_id,
                "complete feature requires acceptance_tests".to_string(),
            );
        }
        if is_complete && row.evidence_paths.is_empty() {
            push_violation(
                "R_COMPLETE_EVIDENCE",
                &row.feature_id,
                "complete feature requires evidence_paths".to_string(),
            );
        }
    }

    Ok(ParityVerifyReport {
        ok: violations.is_empty(),
        checked_features: rows.len(),
        violations,
        violations_struct,
    })
}

pub(crate) fn parity_verify_report() -> Result<ParityVerifyReport, String> {
    let dir = parity_dir();
    parity_verify_report_from_dir(&dir)
}
