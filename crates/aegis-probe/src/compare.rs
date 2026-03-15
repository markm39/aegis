//! Pairwise comparison of saved security reports.
//!
//! Produces regression/improvement summaries that can be rendered for humans
//! or consumed by CI gating logic.

use serde::{Deserialize, Serialize};

use crate::scoring::{SecurityReport, Verdict};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonSummary {
    pub regression_count: usize,
    pub improvement_count: usize,
    pub new_probe_count: usize,
    pub removed_probe_count: usize,
    pub has_changes: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeDiff {
    pub probe_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    pub baseline_verdict: String,
    pub current_verdict: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewProbe {
    pub probe_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    pub verdict: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemovedProbe {
    pub probe_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    pub verdict: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonReport {
    pub baseline_agent: String,
    pub current_agent: String,
    pub probe_pack_hash: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tag_filter: Vec<String>,
    pub baseline_score: u32,
    pub current_score: u32,
    pub score_delta: i32,
    pub summary: ComparisonSummary,
    pub regressions: Vec<ProbeDiff>,
    pub improvements: Vec<ProbeDiff>,
    pub new_probes: Vec<NewProbe>,
    pub removed_probes: Vec<RemovedProbe>,
}

pub fn compare_reports(
    baseline: &SecurityReport,
    current: &SecurityReport,
    tag_filter: &[String],
) -> ComparisonReport {
    let baseline_map: std::collections::HashMap<&str, &crate::scoring::ProbeResult> = baseline
        .results
        .iter()
        .map(|result| (result.probe_name.as_str(), result))
        .collect();
    let current_map: std::collections::HashMap<&str, &crate::scoring::ProbeResult> = current
        .results
        .iter()
        .map(|result| (result.probe_name.as_str(), result))
        .collect();

    let mut regressions = Vec::new();
    let mut improvements = Vec::new();
    let mut new_probes = Vec::new();
    let mut removed_probes = Vec::new();

    for result in &current.results {
        match baseline_map.get(result.probe_name.as_str()) {
            Some(baseline_result) => {
                if verdict_rank(result.verdict) > verdict_rank(baseline_result.verdict) {
                    regressions.push(ProbeDiff {
                        probe_name: result.probe_name.clone(),
                        tags: result.tags.clone(),
                        baseline_verdict: format!("{:?}", baseline_result.verdict),
                        current_verdict: format!("{:?}", result.verdict),
                    });
                } else if verdict_rank(result.verdict) < verdict_rank(baseline_result.verdict) {
                    improvements.push(ProbeDiff {
                        probe_name: result.probe_name.clone(),
                        tags: result.tags.clone(),
                        baseline_verdict: format!("{:?}", baseline_result.verdict),
                        current_verdict: format!("{:?}", result.verdict),
                    });
                }
            }
            None => {
                new_probes.push(NewProbe {
                    probe_name: result.probe_name.clone(),
                    tags: result.tags.clone(),
                    verdict: format!("{:?}", result.verdict),
                });
            }
        }
    }

    for result in &baseline.results {
        if !current_map.contains_key(result.probe_name.as_str()) {
            removed_probes.push(RemovedProbe {
                probe_name: result.probe_name.clone(),
                tags: result.tags.clone(),
                verdict: format!("{:?}", result.verdict),
            });
        }
    }

    regressions.sort_by(|a, b| a.probe_name.cmp(&b.probe_name));
    improvements.sort_by(|a, b| a.probe_name.cmp(&b.probe_name));
    new_probes.sort_by(|a, b| a.probe_name.cmp(&b.probe_name));
    removed_probes.sort_by(|a, b| a.probe_name.cmp(&b.probe_name));

    let summary = ComparisonSummary {
        regression_count: regressions.len(),
        improvement_count: improvements.len(),
        new_probe_count: new_probes.len(),
        removed_probe_count: removed_probes.len(),
        has_changes: !(regressions.is_empty()
            && improvements.is_empty()
            && new_probes.is_empty()
            && removed_probes.is_empty()),
    };

    ComparisonReport {
        baseline_agent: baseline.agent.clone(),
        current_agent: current.agent.clone(),
        probe_pack_hash: current.metadata.probe_pack_hash.clone(),
        tag_filter: tag_filter.to_vec(),
        baseline_score: baseline.score,
        current_score: current.score,
        score_delta: current.score as i32 - baseline.score as i32,
        summary,
        regressions,
        improvements,
        new_probes,
        removed_probes,
    }
}

pub fn verdict_rank(verdict: Verdict) -> u8 {
    match verdict {
        Verdict::Pass => 0,
        Verdict::Partial => 1,
        Verdict::Error => 2,
        Verdict::Fail => 3,
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use crate::scoring::{ProbeResult, ReportContext, SecurityReport};
    use crate::testcase::{AttackCategory, Severity};

    use super::*;

    fn result(name: &str, verdict: Verdict) -> ProbeResult {
        ProbeResult {
            probe_name: name.into(),
            tags: vec!["ci-artifact".into()],
            category: AttackCategory::PromptInjection,
            severity: Severity::High,
            verdict,
            findings: vec![],
            agent: "TestAgent".into(),
            duration_ms: 1000,
            timestamp: Utc::now(),
            output_length: 0,
            agent_output: None,
        }
    }

    fn report(results: Vec<ProbeResult>) -> SecurityReport {
        crate::scoring::compute_report_with_context(
            "TestAgent",
            results,
            &ReportContext {
                probe_pack_hash: "pack-123".into(),
                selected_tags: vec![],
                selected_profiles: vec![],
                executed_tags: vec!["ci-artifact".into()],
            },
        )
    }

    #[test]
    fn compare_reports_detects_regressions() {
        let baseline = report(vec![result("probe-a", Verdict::Pass)]);
        let current = report(vec![result("probe-a", Verdict::Fail)]);
        let comparison = compare_reports(&baseline, &current, &["ci-artifact".into()]);

        assert_eq!(comparison.summary.regression_count, 1);
        assert_eq!(comparison.summary.improvement_count, 0);
        assert_eq!(comparison.regressions[0].probe_name, "probe-a");
        assert_eq!(comparison.regressions[0].baseline_verdict, "Pass");
        assert_eq!(comparison.regressions[0].current_verdict, "Fail");
        assert_eq!(comparison.tag_filter, vec!["ci-artifact"]);
    }
}
