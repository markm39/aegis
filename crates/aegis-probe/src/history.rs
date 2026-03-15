//! Longitudinal analysis across saved security reports.
//!
//! Provides trend summaries, regression detection, and probe instability
//! analysis for a sequence of compatible saved reports.

use serde::{Deserialize, Serialize};

use crate::scoring::{SecurityReport, Verdict};
use crate::stats;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryWindow {
    pub first_timestamp: chrono::DateTime<chrono::Utc>,
    pub latest_timestamp: chrono::DateTime<chrono::Utc>,
    pub probe_pack_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NumericTrend {
    pub first: f64,
    pub latest: f64,
    pub delta: f64,
    pub mean: f64,
    pub min: f64,
    pub max: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryTrend {
    pub category: String,
    pub first_pass_rate: f64,
    pub latest_pass_rate: f64,
    pub delta: f64,
    pub mean_pass_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeRegression {
    pub probe_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    pub baseline_verdict: String,
    pub latest_verdict: String,
    pub pass_rate: f64,
    pub fail_rate: f64,
    pub error_rate: f64,
    pub verdict_stability: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnstableProbe {
    pub probe_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    pub pass_rate: f64,
    pub fail_rate: f64,
    pub error_rate: f64,
    pub verdict_stability: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryReport {
    pub agent: String,
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

pub fn analyze_history(runs: &[SecurityReport], tag_filter: &[String]) -> HistoryReport {
    assert!(
        !runs.is_empty(),
        "analyze_history requires at least one saved report"
    );

    let aggregate = stats::aggregate_runs(runs);
    let first = &runs[0];
    let latest = &runs[runs.len() - 1];

    let score_samples: Vec<f64> = runs.iter().map(|run| run.score as f64).collect();
    let pass_rate_samples: Vec<f64> = runs.iter().map(overall_pass_rate).collect();

    let score = numeric_trend(&score_samples);
    let overall_pass_rate = numeric_trend(&pass_rate_samples);

    let mut category_trends = aggregate
        .aggregate
        .category_pass_rates
        .iter()
        .map(|category| CategoryTrend {
            category: category.category.clone(),
            first_pass_rate: category_pass_rate(first, &category.category),
            latest_pass_rate: category_pass_rate(latest, &category.category),
            delta: category_pass_rate(latest, &category.category)
                - category_pass_rate(first, &category.category),
            mean_pass_rate: category.pass_rate.mean,
        })
        .collect::<Vec<_>>();
    category_trends.sort_by(|a, b| a.category.cmp(&b.category));

    let mut regressions = aggregate
        .probe_stats
        .iter()
        .filter_map(|probe| {
            let baseline = first
                .results
                .iter()
                .find(|result| result.probe_name == probe.probe_name)?;
            let current = latest
                .results
                .iter()
                .find(|result| result.probe_name == probe.probe_name)?;

            if verdict_rank(current.verdict) <= verdict_rank(baseline.verdict) {
                return None;
            }

            Some(ProbeRegression {
                probe_name: probe.probe_name.clone(),
                tags: current.tags.clone(),
                baseline_verdict: format!("{:?}", baseline.verdict),
                latest_verdict: format!("{:?}", current.verdict),
                pass_rate: probe.pass_rate,
                fail_rate: probe.fail_rate,
                error_rate: probe.error_rate,
                verdict_stability: probe.verdict_stability,
            })
        })
        .collect::<Vec<_>>();
    regressions.sort_by(|a, b| {
        b.fail_rate
            .partial_cmp(&a.fail_rate)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.probe_name.cmp(&b.probe_name))
    });

    let mut unstable_probes = aggregate
        .probe_stats
        .iter()
        .filter(|probe| probe.verdict_stability < 1.0)
        .map(|probe| {
            let tags = latest
                .results
                .iter()
                .find(|result| result.probe_name == probe.probe_name)
                .map(|result| result.tags.clone())
                .unwrap_or_default();
            UnstableProbe {
                probe_name: probe.probe_name.clone(),
                tags,
                pass_rate: probe.pass_rate,
                fail_rate: probe.fail_rate,
                error_rate: probe.error_rate,
                verdict_stability: probe.verdict_stability,
            }
        })
        .collect::<Vec<_>>();
    unstable_probes.sort_by(|a, b| {
        a.verdict_stability
            .partial_cmp(&b.verdict_stability)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                b.fail_rate
                    .partial_cmp(&a.fail_rate)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| a.probe_name.cmp(&b.probe_name))
    });

    HistoryReport {
        agent: latest.agent.clone(),
        run_count: runs.len(),
        tag_filter: tag_filter.to_vec(),
        window: HistoryWindow {
            first_timestamp: first.timestamp,
            latest_timestamp: latest.timestamp,
            probe_pack_hash: latest.metadata.probe_pack_hash.clone(),
        },
        score,
        overall_pass_rate,
        category_trends,
        regressions,
        unstable_probes,
        generated_at: chrono::Utc::now().to_rfc3339(),
    }
}

fn numeric_trend(samples: &[f64]) -> NumericTrend {
    let stats = stats::descriptive_stats(samples);
    let first = samples.first().copied().unwrap_or(0.0);
    let latest = samples.last().copied().unwrap_or(0.0);
    NumericTrend {
        first,
        latest,
        delta: latest - first,
        mean: stats.mean,
        min: stats.min,
        max: stats.max,
    }
}

fn overall_pass_rate(report: &SecurityReport) -> f64 {
    if report.results.is_empty() {
        return 0.0;
    }
    report
        .results
        .iter()
        .filter(|result| result.verdict == Verdict::Pass)
        .count() as f64
        / report.results.len() as f64
}

fn category_pass_rate(report: &SecurityReport, category: &str) -> f64 {
    let matching = report
        .results
        .iter()
        .filter(|result| format!("{:?}", result.category) == category)
        .collect::<Vec<_>>();
    if matching.is_empty() {
        return 0.0;
    }
    matching
        .iter()
        .filter(|result| result.verdict == Verdict::Pass)
        .count() as f64
        / matching.len() as f64
}

fn verdict_rank(verdict: Verdict) -> u8 {
    match verdict {
        Verdict::Pass => 0,
        Verdict::Partial => 1,
        Verdict::Fail => 2,
        Verdict::Error => 3,
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use crate::scoring::{ProbeResult, ReportContext, ReportMetadata, SecurityReport};
    use crate::testcase::{AttackCategory, Severity};

    use super::*;

    fn make_result(
        probe_name: &str,
        tags: &[&str],
        category: AttackCategory,
        verdict: Verdict,
    ) -> ProbeResult {
        ProbeResult {
            probe_name: probe_name.into(),
            tags: tags.iter().map(|tag| tag.to_string()).collect(),
            category,
            severity: Severity::High,
            verdict,
            findings: vec![],
            agent: "TestAgent".into(),
            duration_ms: 1000,
            timestamp: Utc::now(),
            output_length: 10,
            agent_output: None,
        }
    }

    fn make_report(timestamp: &str, results: Vec<ProbeResult>) -> SecurityReport {
        let context = ReportContext {
            probe_pack_hash: "pack-123".into(),
            selected_tags: vec![],
            executed_tags: vec!["ci-artifact".into(), "sbom".into()],
        };
        let mut report =
            crate::scoring::compute_report_with_context("TestAgent", results, &context);
        report.timestamp = chrono::DateTime::parse_from_rfc3339(timestamp)
            .unwrap()
            .with_timezone(&Utc);
        report.metadata = ReportMetadata::from_context(&context);
        report
    }

    #[test]
    fn analyze_history_detects_regressions_and_instability() {
        let runs = vec![
            make_report(
                "2026-03-13T00:00:00Z",
                vec![
                    make_result(
                        "sbom-probe",
                        &["sbom", "ci-artifact"],
                        AttackCategory::PromptInjection,
                        Verdict::Pass,
                    ),
                    make_result(
                        "gradle-probe",
                        &["ci-artifact"],
                        AttackCategory::SupplyChain,
                        Verdict::Pass,
                    ),
                ],
            ),
            make_report(
                "2026-03-14T00:00:00Z",
                vec![
                    make_result(
                        "sbom-probe",
                        &["sbom", "ci-artifact"],
                        AttackCategory::PromptInjection,
                        Verdict::Fail,
                    ),
                    make_result(
                        "gradle-probe",
                        &["ci-artifact"],
                        AttackCategory::SupplyChain,
                        Verdict::Pass,
                    ),
                ],
            ),
        ];

        let report = analyze_history(&runs, &["sbom".into()]);
        assert_eq!(report.run_count, 2);
        assert_eq!(report.tag_filter, vec!["sbom"]);
        assert_eq!(report.regressions.len(), 1);
        assert_eq!(report.regressions[0].probe_name, "sbom-probe");
        assert_eq!(report.regressions[0].baseline_verdict, "Pass");
        assert_eq!(report.regressions[0].latest_verdict, "Fail");
        assert!(report
            .unstable_probes
            .iter()
            .any(|probe| probe.probe_name == "sbom-probe"));
        assert_eq!(report.window.probe_pack_hash, "pack-123");
        assert!(report.score.delta < 0.0);
    }
}
