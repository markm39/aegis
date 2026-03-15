//! Baseline bundle creation and local store management.
//!
//! Baselines are stored as immutable bundles plus an index so CI can promote a
//! known-good report and later fetch the latest compatible baseline by agent and
//! selection profile.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::scoring::{ReportSummary, SecurityReport};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineBundle {
    pub schema_version: u32,
    pub metadata: BaselineMetadata,
    pub report: SecurityReport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineMetadata {
    pub name: String,
    pub agent: String,
    pub probe_pack_hash: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selected_tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selected_profiles: Vec<String>,
    pub promoted_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_report: Option<String>,
    pub score: u32,
    pub summary: ReportSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineStoreIndex {
    pub schema_version: u32,
    pub entries: Vec<BaselineIndexEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineIndexEntry {
    pub bundle_path: String,
    pub name: String,
    pub agent: String,
    pub probe_pack_hash: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selected_tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selected_profiles: Vec<String>,
    pub promoted_at: String,
    pub score: u32,
}

#[derive(Debug, Clone, Default)]
pub struct BaselineQuery {
    pub agent: String,
    pub name: Option<String>,
    pub selected_tags: Vec<String>,
    pub selected_profiles: Vec<String>,
}

pub fn bundle_from_report(
    report: &SecurityReport,
    name: &str,
    notes: Option<String>,
    source_report: Option<String>,
) -> BaselineBundle {
    BaselineBundle {
        schema_version: 1,
        metadata: BaselineMetadata {
            name: name.to_string(),
            agent: report.agent.clone(),
            probe_pack_hash: report.metadata.probe_pack_hash.clone(),
            selected_tags: report.metadata.selected_tags.clone(),
            selected_profiles: report.metadata.selected_profiles.clone(),
            promoted_at: chrono::Utc::now().to_rfc3339(),
            notes,
            source_report,
            score: report.score,
            summary: report.summary.clone(),
        },
        report: report.clone(),
    }
}

pub fn read_bundle(path: &Path) -> Result<BaselineBundle, String> {
    let data = std::fs::read_to_string(path)
        .map_err(|err| format!("Error reading {}: {err}", path.display()))?;
    serde_json::from_str(&data).map_err(|err| format!("Error parsing {}: {err}", path.display()))
}

pub fn write_bundle(path: &Path, bundle: &BaselineBundle) -> Result<(), String> {
    let json = serde_json::to_string_pretty(bundle)
        .map_err(|err| format!("Error serializing baseline bundle: {err}"))?;

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("Error creating {}: {err}", parent.display()))?;
    }

    std::fs::write(path, json.as_bytes())
        .map_err(|err| format!("Error writing {}: {err}", path.display()))
}

pub fn publish_bundle(bundle_path: &Path, store_dir: &Path) -> Result<PathBuf, String> {
    let bundle = read_bundle(bundle_path)?;
    std::fs::create_dir_all(store_dir)
        .map_err(|err| format!("Error creating {}: {err}", store_dir.display()))?;

    let bundles_dir = store_dir.join("bundles");
    std::fs::create_dir_all(&bundles_dir)
        .map_err(|err| format!("Error creating {}: {err}", bundles_dir.display()))?;

    let file_name = format!(
        "{}-{}-{}.json",
        sanitize_name(&bundle.metadata.agent),
        sanitize_name(&bundle.metadata.name),
        chrono::Utc::now().format("%Y%m%d%H%M%S")
    );
    let destination = bundles_dir.join(file_name);
    write_bundle(&destination, &bundle)?;

    let mut index = load_index(store_dir)?;
    let relative_path = destination
        .strip_prefix(store_dir)
        .unwrap_or(&destination)
        .to_string_lossy()
        .replace('\\', "/");

    index.entries.push(BaselineIndexEntry {
        bundle_path: relative_path,
        name: bundle.metadata.name.clone(),
        agent: bundle.metadata.agent.clone(),
        probe_pack_hash: bundle.metadata.probe_pack_hash.clone(),
        selected_tags: bundle.metadata.selected_tags.clone(),
        selected_profiles: bundle.metadata.selected_profiles.clone(),
        promoted_at: bundle.metadata.promoted_at.clone(),
        score: bundle.metadata.score,
    });

    write_index(store_dir, &index)?;
    Ok(destination)
}

pub fn fetch_bundle(
    store_dir: &Path,
    query: &BaselineQuery,
) -> Result<(BaselineIndexEntry, BaselineBundle, PathBuf), String> {
    let index = load_index(store_dir)?;
    let entry = index
        .entries
        .iter()
        .filter(|entry| entry.agent.eq_ignore_ascii_case(&query.agent))
        .filter(|entry| {
            query
                .name
                .as_ref()
                .is_none_or(|name| entry.name.eq_ignore_ascii_case(name))
        })
        .filter(|entry| {
            query.selected_tags.iter().all(|tag| {
                entry
                    .selected_tags
                    .iter()
                    .any(|value| value.eq_ignore_ascii_case(tag))
            })
        })
        .filter(|entry| {
            query.selected_profiles.iter().all(|profile| {
                entry
                    .selected_profiles
                    .iter()
                    .any(|value| value.eq_ignore_ascii_case(profile))
            })
        })
        .max_by(|left, right| left.promoted_at.cmp(&right.promoted_at))
        .cloned()
        .ok_or_else(|| {
            format!(
                "No baseline found in {} for agent '{}'{}{}.",
                store_dir.display(),
                query.agent,
                query
                    .name
                    .as_ref()
                    .map(|name| format!(", name '{name}'"))
                    .unwrap_or_default(),
                format_selection_suffix(&query.selected_tags, &query.selected_profiles),
            )
        })?;

    let path = store_dir.join(&entry.bundle_path);
    let bundle = read_bundle(&path)?;
    Ok((entry, bundle, path))
}

pub fn load_index(store_dir: &Path) -> Result<BaselineStoreIndex, String> {
    let index_path = store_dir.join("index.json");
    if !index_path.exists() {
        return Ok(BaselineStoreIndex {
            schema_version: 1,
            entries: Vec::new(),
        });
    }

    let data = std::fs::read_to_string(&index_path)
        .map_err(|err| format!("Error reading {}: {err}", index_path.display()))?;
    serde_json::from_str(&data)
        .map_err(|err| format!("Error parsing {}: {err}", index_path.display()))
}

fn write_index(store_dir: &Path, index: &BaselineStoreIndex) -> Result<(), String> {
    let index_path = store_dir.join("index.json");
    let json = serde_json::to_string_pretty(index)
        .map_err(|err| format!("Error serializing baseline index: {err}"))?;
    std::fs::write(&index_path, json.as_bytes())
        .map_err(|err| format!("Error writing {}: {err}", index_path.display()))
}

fn sanitize_name(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();

    sanitized
        .split('-')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

fn format_selection_suffix(tags: &[String], profiles: &[String]) -> String {
    let mut parts = Vec::new();
    if !tags.is_empty() {
        parts.push(format!(" tags [{}]", tags.join(", ")));
    }
    if !profiles.is_empty() {
        parts.push(format!(" profiles [{}]", profiles.join(", ")));
    }
    parts.concat()
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use crate::scoring::{PlatformMetadata, ReportMetadata, SecurityReport};

    use super::*;

    fn sample_report() -> SecurityReport {
        SecurityReport {
            score: 92,
            agent: "ClaudeCode".into(),
            metadata: ReportMetadata {
                schema_version: 3,
                runner_version: "0.1.0".into(),
                probe_pack_hash: "pack-123".into(),
                selected_tags: vec!["ci-artifact".into()],
                selected_profiles: vec!["github-actions".into()],
                executed_tags: vec!["ci-artifact".into(), "sbom".into()],
                platform: PlatformMetadata {
                    os: "macos".into(),
                    arch: "arm64".into(),
                },
                ci: None,
            },
            results: vec![],
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

    #[test]
    fn publish_and_fetch_bundle_round_trip() {
        let dir = tempfile::TempDir::new().unwrap();
        let bundle_path = dir.path().join("baseline.bundle.json");
        let report = sample_report();
        let bundle = bundle_from_report(&report, "main", Some("stable".into()), None);
        write_bundle(&bundle_path, &bundle).unwrap();

        let store_dir = dir.path().join("store");
        publish_bundle(&bundle_path, &store_dir).unwrap();

        let (entry, fetched, stored_path) = fetch_bundle(
            &store_dir,
            &BaselineQuery {
                agent: "claudecode".into(),
                name: Some("main".into()),
                selected_tags: vec!["ci-artifact".into()],
                selected_profiles: vec!["github-actions".into()],
            },
        )
        .unwrap();

        assert_eq!(entry.name, "main");
        assert_eq!(fetched.metadata.name, "main");
        assert_eq!(fetched.report.agent, "ClaudeCode");
        assert!(stored_path.exists());
    }

    #[test]
    fn fetch_bundle_reports_missing_selection() {
        let dir = tempfile::TempDir::new().unwrap();
        let error = fetch_bundle(
            dir.path(),
            &BaselineQuery {
                agent: "ClaudeCode".into(),
                name: Some("missing".into()),
                selected_tags: vec![],
                selected_profiles: vec!["github-actions".into()],
            },
        )
        .unwrap_err();

        assert!(error.contains("No baseline found"));
    }
}
